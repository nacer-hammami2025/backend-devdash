const nodemailer = require('nodemailer');
const logger = require('./logger');

class Mailer {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  async sendEmail({ to, subject, text, html }) {
    try {
      const info = await this.transporter.sendMail({
        from: `"DevDash" <${process.env.SMTP_FROM}>`,
        to,
        subject,
        text,
        html
      });

      logger.info('Email sent successfully', { messageId: info.messageId });
      return info;
    } catch (error) {
      logger.error('Error sending email:', error);
      throw error;
    }
  }
}

module.exports = new Mailer();
