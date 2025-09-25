const mongoose = require('mongoose');

const taskSuggestionSchema = new mongoose.Schema({
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    basis: { type: String }, // short textual basis (e.g., aggregated context)
    suggestions: [{
        title: String,
        description: String,
        priority: { type: String, enum: ['low', 'medium', 'high'] },
        impact: String,
        effort: String,
        rationale: String
    }],
    generatedAt: { type: Date, default: Date.now },
    model: String,
    tokensUsed: Number
}, { timestamps: true });

module.exports = mongoose.model('TaskSuggestion', taskSuggestionSchema);
