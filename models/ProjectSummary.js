const mongoose = require('mongoose');

const projectSummarySchema = new mongoose.Schema({
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    summary: { type: String, required: true },
    highlights: [{ type: String }],
    risks: [{ type: String }],
    opportunities: [{ type: String }],
    generatedAt: { type: Date, default: Date.now },
    model: String,
    tokensUsed: Number
}, { timestamps: true });

module.exports = mongoose.model('ProjectSummary', projectSummarySchema);
