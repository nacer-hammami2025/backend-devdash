const mongoose = require('mongoose');

const sentimentSchema = new mongoose.Schema({
    label: String, // positive | neutral | negative | mixed
    score: Number
}, { _id: false });

const keywordSchema = new mongoose.Schema({
    term: String,
    weight: Number
}, { _id: false });

const commentAnalysisSchema = new mongoose.Schema({
    task: { type: mongoose.Schema.Types.ObjectId, ref: 'Task', index: true },
    commentId: { type: mongoose.Schema.Types.ObjectId },
    original: String,
    sentiment: sentimentSchema,
    keywords: [keywordSchema],
    classification: [{ label: String, score: Number }],
    generatedAt: { type: Date, default: Date.now },
    model: String,
    tokensUsed: Number
}, { timestamps: true });

module.exports = mongoose.model('CommentAnalysis', commentAnalysisSchema);
