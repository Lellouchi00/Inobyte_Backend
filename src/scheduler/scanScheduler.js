const cron = require("node-cron");
const Alert = require("../models/Alert");
const Scan = require("../models/Scan");
const Website = require("../models/Website");
const {
  buildAlertRecords,
  createStoredReport,
  runScanChecks,
  summarizeAlerts
} = require("../controllers/scanController");
const { emitToUser } = require("../socket");

const DAILY_CHECKS = ["xss", "sql_injection", "missing_https", "missing_security_headers"];
const WEEKLY_CHECKS = ["exposed_directories", "outdated_libraries", "weak_authentication"];

const formatSummary = (report) => (
  `risk=${report.overall_risk}, vulnerable=${report.summary.vulnerable}, safe=${report.summary.safe}, unknown=${report.summary.unknown}`
);

const emitAlerts = (userId, alerts) => {
  for (const alert of alerts) {
    emitToUser(String(userId), "new_alert", {
      id: alert._id,
      websiteId: alert.websiteId,
      message: alert.message,
      severity: alert.severity,
      timestamp: alert.createdAt
    });
  }
};

const processWebsiteScan = async (website, selectedChecks, scanType) => {
  const previousScan = await Scan.findOne({ websiteId: website._id })
    .sort({ createdAt: -1 })
    .select("results");

  const report = await runScanChecks(website.domain, selectedChecks);
  report.alert_message = summarizeAlerts(report, previousScan?.results || null);

  await Scan.create({
    userId: website.userId,
    websiteId: website._id,
    url: report.target_url,
    status: "completed",
    scanType,
    results: report
  });

  await createStoredReport({
    userId: website.userId,
    websiteId: website._id,
    scanType,
    scanReport: report
  });

  if (report.send_alert) {
    const alertRecords = buildAlertRecords(report, website._id, website.userId);
    const alerts = await Alert.insertMany(alertRecords);
    emitAlerts(website.userId, alerts);
  }

  console.log(`[scanScheduler] ${scanType} ${website.domain}: ${formatSummary(report)}`);
};

const runAutomatedScans = async (selectedChecks, scanType) => {
  const websites = await Website.find({ verified: true })
    .select("_id domain userId verified");

  for (const website of websites) {
    if (!website.verified) {
      continue;
    }

    try {
      await processWebsiteScan(website, selectedChecks, scanType);
    } catch (err) {
      console.error(`[scanScheduler] ${scanType} ${website.domain}: failed - ${err.message}`);
    }
  }
};

const scheduleJobs = () => {
  cron.schedule("0 2 * * *", () => {
    runAutomatedScans(DAILY_CHECKS, "daily_auto")
      .catch((err) => console.error(`[scanScheduler] daily_auto job failed - ${err.message}`));
  });

  cron.schedule("0 3 * * 0", () => {
    runAutomatedScans(WEEKLY_CHECKS, "weekly_auto")
      .catch((err) => console.error(`[scanScheduler] weekly_auto job failed - ${err.message}`));
  });

  console.log("[scanScheduler] Scheduled daily scans at 02:00 and weekly scans at 03:00 on Sundays");
};

if (process.env.NODE_ENV !== "test") {
  scheduleJobs();
}

module.exports = {
  DAILY_CHECKS,
  WEEKLY_CHECKS,
  runAutomatedScans,
  scheduleJobs
};
