const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const Chart = require('chart.js');
const Task = require('../models/Task');
const Project = require('../models/Project');
const User = require('../models/User');

class ReportGenerator {
  constructor() {
    this.reportTypes = new Map([
      ['performance', this.generatePerformanceReport.bind(this)],
      ['progress', this.generateProgressReport.bind(this)],
      ['resource', this.generateResourceReport.bind(this)],
      ['quality', this.generateQualityReport.bind(this)],
      ['forecast', this.generateForecastReport.bind(this)]
    ]);
  }

  async generateReport(type, options) {
    const generator = this.reportTypes.get(type);
    if (!generator) {
      throw new Error(`Type de rapport non supporté: ${type}`);
    }
    return generator.call(this, options);
  }

  async generatePerformanceReport({ startDate, endDate, projectId }) {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Performance');

    // Récupérer les données
    const tasks = await Task.find({
      createdAt: { $gte: startDate, $lte: endDate },
      project: projectId
    }).populate('assignedTo');

    // Métriques de performance
    const metrics = this.calculatePerformanceMetrics(tasks);

    // En-têtes
    worksheet.columns = [
      { header: 'Métrique', key: 'metric', width: 30 },
      { header: 'Valeur', key: 'value', width: 20 },
      { header: 'Tendance', key: 'trend', width: 20 }
    ];

    // Ajouter les données
    Object.entries(metrics).forEach(([metric, data]) => {
      worksheet.addRow({
        metric,
        value: data.value,
        trend: data.trend
      });
    });

    // Ajouter des graphiques
    const performanceChart = await this.createPerformanceChart(metrics);
    worksheet.addImage(performanceChart, {
      tl: { col: 4, row: 1 },
      br: { col: 8, row: 15 }
    });

    return workbook;
  }

  async generateProgressReport({ project }) {
    const doc = new PDFDocument();

    // En-tête du rapport
    doc.fontSize(20).text('Rapport de Progression du Projet', {
      align: 'center'
    });

    // Résumé du projet
    const projectStats = await this.getProjectStats(project);
    doc.moveDown()
      .fontSize(14).text('Résumé du Projet')
      .fontSize(12)
      .text(`Progression globale: ${projectStats.progress}%`)
      .text(`Tâches complétées: ${projectStats.completedTasks}/${projectStats.totalTasks}`)
      .text(`Temps estimé restant: ${projectStats.remainingTime} heures`);

    // Milestone timeline
    await this.addMilestoneTimeline(doc, project);

    // Graphiques de progression
    const progressChart = await this.createProgressChart(projectStats);
    doc.addImage(progressChart, {
      fit: [500, 300],
      align: 'center'
    });

    // Risques et blocages
    const risks = await this.analyzeProjectRisks(project);
    doc.addPage()
      .fontSize(14).text('Risques et Blocages')
      .fontSize(12);
    
    risks.forEach(risk => {
      doc.moveDown()
        .text(`${risk.severity}: ${risk.description}`)
        .text(`Impact: ${risk.impact}`)
        .text(`Mitigation: ${risk.mitigation}`);
    });

    return doc;
  }

  async generateResourceReport({ timeframe = 'month' }) {
    const workbook = new ExcelJS.Workbook();
    
    // Feuille de charge de travail
    const workloadSheet = workbook.addWorksheet('Charge de travail');
    const workloadData = await this.calculateWorkload(timeframe);
    
    workloadSheet.columns = [
      { header: 'Ressource', key: 'resource', width: 20 },
      { header: 'Capacité', key: 'capacity', width: 15 },
      { header: 'Allocation', key: 'allocation', width: 15 },
      { header: 'Disponibilité', key: 'availability', width: 15 }
    ];

    workloadData.forEach(data => workloadSheet.addRow(data));

    // Feuille de compétences
    const skillsSheet = workbook.addWorksheet('Matrice de compétences');
    const skillsMatrix = await this.generateSkillsMatrix();
    
    // Ajouter la matrice de compétences
    skillsMatrix.headers.forEach((header, index) => {
      skillsSheet.getColumn(index + 2).header = header;
      skillsSheet.getColumn(index + 2).width = 15;
    });

    skillsMatrix.data.forEach(row => skillsSheet.addRow(row));

    // Feuille de prévisions
    const forecastSheet = workbook.addWorksheet('Prévisions');
    const forecastData = await this.generateResourceForecast();
    
    forecastSheet.columns = [
      { header: 'Période', key: 'period', width: 15 },
      { header: 'Besoin estimé', key: 'need', width: 20 },
      { header: 'Disponibilité', key: 'availability', width: 20 },
      { header: 'Écart', key: 'gap', width: 15 }
    ];

    forecastData.forEach(data => forecastSheet.addRow(data));

    return workbook;
  }

  async generateQualityReport({ project, period }) {
    const doc = new PDFDocument();
    
    // Métriques de qualité
    const metrics = await this.calculateQualityMetrics(project, period);

    doc.fontSize(20).text('Rapport de Qualité', { align: 'center' });

    // KPIs principaux
    doc.moveDown()
      .fontSize(14).text('Indicateurs Clés de Performance')
      .fontSize(12)
      .text(`Taux de défauts: ${metrics.defectRate}%`)
      .text(`Temps moyen de résolution: ${metrics.avgResolutionTime} heures`)
      .text(`Satisfaction utilisateur: ${metrics.userSatisfaction}%`)
      .text(`Couverture de tests: ${metrics.testCoverage}%`);

    // Tendances de qualité
    const qualityTrends = await this.generateQualityTrends(project, period);
    const trendChart = await this.createTrendChart(qualityTrends);
    doc.addImage(trendChart, {
      fit: [500, 300],
      align: 'center'
    });

    // Analyse des causes racines
    const rootCauses = await this.analyzeRootCauses(project, period);
    doc.addPage()
      .fontSize(14).text('Analyse des Causes Racines')
      .fontSize(12);

    rootCauses.forEach(cause => {
      doc.moveDown()
        .text(`Problème: ${cause.issue}`)
        .text(`Fréquence: ${cause.frequency} occurrences`)
        .text(`Impact: ${cause.impact}`)
        .text(`Solutions proposées: ${cause.solutions.join(', ')}`);
    });

    return doc;
  }

  async generateForecastReport({ project, horizon = 3 }) {
    const workbook = new ExcelJS.Workbook();
    
    // Prévisions générales
    const forecastSheet = workbook.addWorksheet('Prévisions');
    const forecasts = await this.generateProjectForecasts(project, horizon);
    
    forecastSheet.columns = [
      { header: 'Métrique', key: 'metric', width: 25 },
      { header: 'Actuel', key: 'current', width: 15 },
      { header: 'Prévu (1M)', key: 'forecast1m', width: 15 },
      { header: 'Prévu (3M)', key: 'forecast3m', width: 15 },
      { header: 'Tendance', key: 'trend', width: 15 }
    ];

    forecasts.forEach(forecast => forecastSheet.addRow(forecast));

    // Analyse des risques
    const riskSheet = workbook.addWorksheet('Analyse des risques');
    const risks = await this.analyzeProjectRisks(project);
    
    riskSheet.columns = [
      { header: 'Risque', key: 'risk', width: 30 },
      { header: 'Probabilité', key: 'probability', width: 15 },
      { header: 'Impact', key: 'impact', width: 15 },
      { header: 'Score', key: 'score', width: 15 },
      { header: 'Mitigation', key: 'mitigation', width: 40 }
    ];

    risks.forEach(risk => riskSheet.addRow(risk));

    return workbook;
  }

  // Méthodes utilitaires
  async calculatePerformanceMetrics(tasks) {
    // ... Implémentation des calculs de métriques
  }

  async getProjectStats(project) {
    // ... Implémentation des statistiques de projet
  }

  async analyzeProjectRisks(project) {
    // ... Implémentation de l'analyse des risques
  }

  async calculateWorkload(timeframe) {
    // ... Implémentation du calcul de charge
  }

  async generateSkillsMatrix() {
    // ... Implémentation de la matrice de compétences
  }

  async generateResourceForecast() {
    // ... Implémentation des prévisions de ressources
  }

  async calculateQualityMetrics(project, period) {
    // ... Implémentation des métriques de qualité
  }

  async analyzeRootCauses(project, period) {
    // ... Implémentation de l'analyse des causes racines
  }

  async generateProjectForecasts(project, horizon) {
    // ... Implémentation des prévisions de projet
  }
}

module.exports = new ReportGenerator();
