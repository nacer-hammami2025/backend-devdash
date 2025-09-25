// aiService.js
// Higher-level AI orchestration: summaries, suggestions, comment analysis

const Project = require('../models/Project');
const Task = require('../models/Task');
const ProjectSummary = require('../models/ProjectSummary');
const TaskSuggestion = require('../models/TaskSuggestion');
const CommentAnalysis = require('../models/CommentAnalysis');
const { AIProvider } = require('./aiProvider');
const { z } = require('zod');
// Zod schemas for validation & repair
const SuggestionSchema = z.object({
    title: z.string().min(1).max(160),
    description: z.string().min(1).max(800).optional(),
    priority: z.enum(['low', 'medium', 'high']).optional(),
    impact: z.string().max(120).optional(),
    effort: z.string().max(60).optional(),
    rationale: z.string().max(400).optional()
});
const SuggestionsArraySchema = z.array(SuggestionSchema).min(1).max(10);

function safeJSONParse(text) {
    try { return JSON.parse(text); } catch { return null; }
}

function repairJSONList(raw) {
    // Try to extract JSON array block
    const match = raw.match(/\[[\s\S]*\]/);
    if (match) {
        const parsed = safeJSONParse(match[0]);
        if (parsed) return parsed;
    }
    // Fallback: bullet lines => objects
    const lines = raw.split(/\n/).map(l => l.trim()).filter(l => l);
    return lines.slice(0, 5).map(l => ({ title: l.replace(/^[*\-•\d.\s]+/, '').slice(0, 160) }));
}

function normalizeSuggestions(suggestions) {
    const result = [];
    for (const s of suggestions) {
        try {
            const norm = SuggestionSchema.parse({
                title: (s.title || s.name || '').toString().trim().slice(0, 160),
                description: s.description ? s.description.toString().slice(0, 800) : undefined,
                priority: ['low', 'medium', 'high'].includes((s.priority || '').toLowerCase()) ? s.priority.toLowerCase() : undefined,
                impact: s.impact ? s.impact.toString().slice(0, 120) : undefined,
                effort: s.effort ? s.effort.toString().slice(0, 60) : undefined,
                rationale: s.rationale ? s.rationale.toString().slice(0, 400) : undefined
            });
            if (norm.title) result.push(norm);
        } catch (_) { /* drop invalid */ }
        if (result.length >= 10) break;
    }
    return result.length ? result : [{ title: 'Aucune suggestion interprétable' }];
}

const provider = new AIProvider();

function parseListSections(text) {
    // Very light parser turning bullet/numbered lines into arrays
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    return lines.filter(l => /^[*\-•]/.test(l) || /^\d+\./.test(l)).map(l => l.replace(/^[*\-•\d.\s]+/, ''));
}

async function generateProjectSummary(projectId) {
    const project = await Project.findById(projectId);
    if (!project) throw new Error('Project not found');
    const tasks = await Task.find({ project: projectId });
    const completed = tasks.filter(t => t.status === 'done').length;
    const inProgress = tasks.filter(t => t.status === 'in_progress').length;

    const prompt = `Projet: ${project.name}\nDescription: ${project.description}\nDeadline: ${project.deadline}\nStatut: ${project.status}\nTâches totales: ${tasks.length}\nTerminées: ${completed}\nEn cours: ${inProgress}\n\nProduit un résumé concis (150 mots max) en français avec sections:\nRésumé général\nPoints forts (liste)\nRisques (liste)\nOpportunités (liste)`;

    const { text, usage } = await provider.complete({
        system: 'Tu es un assistant de productivité projet senior.',
        prompt,
        temperature: 0.5,
        maxTokens: 700
    });

    // Naive section splitting
    const sections = text.split(/\n{2,}/);
    const summary = sections[0];
    const highlights = parseListSections(sections.find(s => /Points forts/i.test(s)) || '');
    const risks = parseListSections(sections.find(s => /Risques/i.test(s)) || '');
    const opportunities = parseListSections(sections.find(s => /Opportunités/i.test(s)) || '');

    return await ProjectSummary.create({
        project: project._id,
        summary,
        highlights,
        risks,
        opportunities,
        model: provider.model,
        tokensUsed: usage.total_tokens
    });
}

async function generateTaskSuggestions(projectId) {
    const project = await Project.findById(projectId);
    if (!project) throw new Error('Project not found');
    const tasks = await Task.find({ project: projectId });
    const context = tasks.slice(0, 30).map(t => `- ${t.title} [${t.status}]`).join('\n');

    const prompt = `Projet: ${project.name}\nObjectif: ${project.description}\nTâches existantes:\n${context}\n\nPropose 5 prochaines tâches stratégiques (JSON strict) avec: title, description, priority (low|medium|high), impact (court, moyen, long), effort (faible|moyen|élevé), rationale (justification).`;

    const { text, usage } = await provider.complete({
        system: 'Assistant de planification agile.',
        prompt,
        temperature: 0.6,
        maxTokens: 800
    });
    // Attempt robust parsing
    let parsed = safeJSONParse(text);
    if (!Array.isArray(parsed)) {
        parsed = repairJSONList(text);
    }
    let valid;
    try { valid = SuggestionsArraySchema.parse(parsed); }
    catch { valid = normalizeSuggestions(parsed); }
    const suggestions = valid.map(s => ({ ...s }));

    return await TaskSuggestion.create({
        project: project._id,
        basis: `Derived from ${tasks.length} tasks`,
        suggestions,
        model: provider.model,
        tokensUsed: usage.total_tokens
    });
}

async function analyzeComment(taskId, commentId) {
    const task = await Task.findById(taskId);
    if (!task) throw new Error('Task not found');
    const comment = task.comments.id(commentId);
    if (!comment) throw new Error('Comment not found');

    const prompt = `Analyse ce commentaire pour un outil de gestion de projet. Retourne du JSON { sentiment:{label,score}, keywords:[{term,weight}], classification:[{label,score}] }.\nCommentaire: "${comment.content}"`;

    const { text, usage } = await provider.complete({
        system: 'Assistant d\'analyse linguistique francophone.',
        prompt,
        temperature: 0.3,
        maxTokens: 500
    });

    let json = safeJSONParse(text);
    if (!json || typeof json !== 'object') {
        json = { sentiment: { label: 'neutral', score: 0.0 }, keywords: [], classification: [] };
    }
    if (!json.sentiment || typeof json.sentiment !== 'object') json.sentiment = { label: 'neutral', score: 0.0 };
    if (!Array.isArray(json.keywords)) json.keywords = [];
    if (!Array.isArray(json.classification)) json.classification = [];

    return await CommentAnalysis.create({
        task: task._id,
        commentId: comment._id,
        original: comment.content,
        sentiment: json.sentiment,
        keywords: json.keywords,
        classification: json.classification,
        model: provider.model,
        tokensUsed: usage.total_tokens
    });
}

module.exports = { generateProjectSummary, generateTaskSuggestions, analyzeComment };
