const User = require('../models/User');
const Project = require('../models/Project');
const Task = require('../models/Task');
const { hashPassword, comparePassword } = require('../utils/auth');

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    
    // Récupérer les statistiques de l'utilisateur
    const stats = {
      projects: {
        total: await Project.countDocuments({ members: req.user._id }),
        managed: await Project.countDocuments({ createdBy: req.user._id }),
        active: await Project.countDocuments({ 
          members: req.user._id, 
          isCompleted: false 
        })
      },
      tasks: {
        total: await Task.countDocuments({ assignedTo: req.user._id }),
        completed: await Task.countDocuments({ 
          assignedTo: req.user._id, 
          status: 'completed' 
        }),
        pending: await Task.countDocuments({
          assignedTo: req.user._id,
          status: { $ne: 'completed' }
        })
      }
    };

    res.json({ user, stats });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { fullName, email, currentPassword, newPassword, skills } = req.body;
    const user = await User.findById(req.user._id);

    // Valider le mot de passe actuel si un nouveau mot de passe est fourni
    if (newPassword) {
      const validPassword = await comparePassword(currentPassword, user.password);
      if (!validPassword) {
        return res.status(400).json({ message: 'Mot de passe actuel incorrect' });
      }
      user.password = await hashPassword(newPassword);
    }

    // Mettre à jour les autres champs
    if (fullName) user.fullName = fullName;
    if (email) user.email = email;
    if (skills) user.skills = skills;

    await user.save();

    // Ne pas renvoyer le mot de passe
    const userResponse = user.toObject();
    delete userResponse.password;

    res.json(userResponse);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.updatePreferences = async (req, res) => {
  try {
    const { preferences } = req.body;
    const user = await User.findById(req.user._id);

    user.preferences = {
      ...user.preferences.toObject(),
      ...preferences
    };
    await user.save();

    res.json(user.preferences);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.updateAvatar = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier envoyé' });
    }

    const user = await User.findById(req.user._id);
    user.avatar = `/avatars/${req.file.filename}`;
    await user.save();

    res.json({ avatar: user.avatar });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Admin only
exports.updateUserRole = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Permission refusée' });
    }

    const { userId } = req.params;
    const { role } = req.body;

    if (!['admin', 'project_manager', 'member'].includes(role)) {
      return res.status(400).json({ message: 'Rôle invalide' });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select('-password');

    res.json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};
