const Notification = require('../models/Notification');

exports.getNotifications = async (req, res) => {
  try {
    const query = { recipient: req.user._id };
    
    // Filtre par lu/non lu si spécifié
    if (req.query.read !== undefined) {
      query.read = req.query.read === 'true';
    }

    const notifications = await Notification.find(query)
      .populate('project', 'name')
      .populate('task', 'title')
      .sort('-createdAt')
      .limit(req.query.limit ? parseInt(req.query.limit) : 50);

    res.json(notifications);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.markAsRead = async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({ message: 'Notification non trouvée' });
    }

    // Vérifier que l'utilisateur est bien le destinataire
    if (notification.recipient.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Accès non autorisé' });
    }

    notification.read = true;
    await notification.save();

    res.json(notification);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.markAllAsRead = async (req, res) => {
  try {
    await Notification.updateMany(
      { recipient: req.user._id, read: false },
      { $set: { read: true } }
    );

    res.json({ message: 'Toutes les notifications ont été marquées comme lues' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.deleteNotification = async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({ message: 'Notification non trouvée' });
    }

    // Vérifier que l'utilisateur est bien le destinataire
    if (notification.recipient.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Accès non autorisé' });
    }

    await notification.remove();
    res.json({ message: 'Notification supprimée' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Utilitaire pour créer une notification
exports.createNotification = async ({
  recipient,
  type,
  title,
  message,
  project = null,
  task = null
}) => {
  try {
    const notification = new Notification({
      recipient,
      type,
      title,
      message,
      project,
      task
    });
    await notification.save();
    return notification;
  } catch (error) {
    console.error('Erreur lors de la création de la notification:', error);
    return null;
  }
};
