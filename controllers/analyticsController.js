const Task = require('../models/Task');
const Activity = require('../models/Activity');

// GET /api/analytics/trends
// Returns 7-day timeseries for created, completed, and in-review activity
exports.getTrends = async (req, res) => {
    try {
        const now = new Date();
        const start = new Date(now);
        start.setDate(start.getDate() - 6); // include today (7 days total)
        start.setHours(0, 0, 0, 0);

        const matchCreated = { createdAt: { $gte: start } };
        const matchCompleted = { updatedAt: { $gte: start }, status: 'done' };
        const matchReview = { updatedAt: { $gte: start }, status: 'in_review' };

        const groupByDay = (dateField) => ([
            { $match: dateField.match },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: `$${dateField.field}` } },
                    count: { $sum: 1 }
                }
            },
            { $project: { _id: 0, day: '$_id', count: 1 } }
        ]);

        const [createdAgg, completedAgg, reviewAgg] = await Promise.all([
            Task.aggregate(groupByDay({ field: 'createdAt', match: matchCreated })),
            Task.aggregate(groupByDay({ field: 'updatedAt', match: matchCompleted })),
            Task.aggregate(groupByDay({ field: 'updatedAt', match: matchReview }))
        ]);

        // Overdue: tasks that became overdue that day (dueDate day), and either not done by end
        // or completed after dueDate.
        const overdueAgg = await Task.aggregate([
            { $match: { dueDate: { $gte: start } } },
            {
                $addFields: {
                    dueDay: { $dateToString: { format: '%Y-%m-%d', date: '$dueDate' } },
                    completedAfterDue: {
                        $cond: [
                            { $eq: ['$status', 'done'] },
                            { $gt: ['$updatedAt', '$dueDate'] },
                            false
                        ]
                    },
                    notDone: { $ne: ['$status', 'done'] }
                }
            },
            { $match: { $or: [{ completedAfterDue: true }, { notDone: true }] } },
            { $group: { _id: '$dueDay', count: { $sum: 1 } } },
            { $project: { _id: 0, day: '$_id', count: 1 } }
        ]);

        // Reopened: infer from activity descriptions mentioning reopen events in the last 7 days
        const reopenedAgg = await Activity.aggregate([
            {
                $match: {
                    createdAt: { $gte: start },
                    type: 'task_status_changed',
                    description: { $regex: /(réouvert|reopen|reopened)/i }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    count: { $sum: 1 }
                }
            },
            { $project: { _id: 0, day: '$_id', count: 1 } }
        ]);

        // Build ordered 7-day series (YYYY-MM-DD)
        const days = [];
        for (let i = 0; i < 7; i++) {
            const d = new Date(start);
            d.setDate(start.getDate() + i);
            const key = d.toISOString().slice(0, 10);
            days.push(key);
        }

        const toSeries = (agg) => days.map((k) => (agg.find((a) => a.day === k)?.count || 0));

        res.json({
            days,
            created: toSeries(createdAgg),
            completed: toSeries(completedAgg),
            inReview: toSeries(reviewAgg),
            overdue: toSeries(overdueAgg),
            reopened: toSeries(reopenedAgg)
        });
    } catch (error) {
        console.error('Error in analytics.getTrends:', error);
        res.status(500).json({ message: error.message });
    }
};
