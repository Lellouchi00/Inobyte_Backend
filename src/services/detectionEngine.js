const path = require("path");
const Alert = require("../models/Alert");

const EXECUTABLE_EXTENSIONS = ["exe", "dll", "scr", "bat", "cmd", "ps1", "msi", "com"];
const DOCUMENT_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"];
const SUSPICIOUS_DOUBLE_EXT = [...EXECUTABLE_EXTENSIONS];

const lower = (v) => String(v || "").toLowerCase().trim();

// استخراج الامتداد الحقيقي
const getExtension = (fileName) => {
  return lower(path.extname(fileName)).replace(".", "");
};

// استخراج كل الامتدادات (لـ double extension)
const getAllExtensions = (fileName) => {
  return lower(fileName).split(".").slice(1);
};

// التحقق من double extension
const hasDoubleExtensionAttack = (fileName) => {
  const exts = getAllExtensions(fileName);

  if (exts.length < 2) return false;

  const lastExt = exts[exts.length - 1];
  const previousExt = exts[exts.length - 2];

  return (
    DOCUMENT_EXTENSIONS.includes(lastExt) &&
    SUSPICIOUS_DOUBLE_EXT.includes(previousExt)
  );
};

// التحقق من mismatch بين الامتداد و MIME
const isMimeMismatch = (extension, mime) => {
  if (!mime) return false;

  const map = {
    pdf: "application/pdf",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    doc: "application/msword",
    txt: "text/plain"
  };

  if (!map[extension]) return false;

  return !mime.includes(map[extension]);
};

const detectMaliciousFileUpload = async (event) => {
  const eventType = lower(event.eventType);

  if (!["file_upload", "upload_attempt", "file_upload_attempt"].includes(eventType)) {
    return null;
  }

  const fileName = event.data?.fileName || event.data?.originalName || "";
  const extension = getExtension(fileName);
  const mimeType = lower(event.data?.mimeType || event.data?.contentType);

  // 1. ملفات تنفيذية مباشرة
  if (EXECUTABLE_EXTENSIONS.includes(extension)) {
    return buildAlert(
      event,
      `Blocked executable file upload: ${fileName}`,
      "high",
      "Dangerous file type uploaded",
      "Executable File Upload Attempt"
    );
  }

  // 2. Double extension attack
  if (hasDoubleExtensionAttack(fileName)) {
    return buildAlert(
      event,
      `Double extension attack detected: ${fileName}`,
      "high",
      "Deceptive file name detected",
      "Double Extension File Upload Attack"
    );
  }

  // 3. MIME mismatch
  if (DOCUMENT_EXTENSIONS.includes(extension) && isMimeMismatch(extension, mimeType)) {
    return buildAlert(
      event,
      `File type mismatch detected: ${fileName}`,
      "medium",
      "File content does not match extension",
      "MIME Type Mismatch"
    );
  }

  // 4. كلمات مشبوهة في الاسم
  const suspiciousKeywords = ["shell", "payload", "hack", "exploit"];
  if (suspiciousKeywords.some(k => fileName.toLowerCase().includes(k))) {
    return buildAlert(
      event,
      `Suspicious file name detected: ${fileName}`,
      "medium",
      "Suspicious file name uploaded",
      "Suspicious Keyword in File Name"
    );
  }

  // 5. flag من antivirus
  if (event.data?.malwareDetected === true) {
    return buildAlert(
      event,
      `Malware detected in uploaded file: ${fileName}`,
      "high",
      "Virus detected in file upload",
      "Malware Detection in File Upload"
    );
  }

  return null;
};

const buildAlert = async (event, message, severity, userTitle, technicalTitle) => {
  return await Alert.create({
    userId: event.userId,
    websiteId: event.websiteId,
    message,
    userTitle,
    technicalTitle,
    severity
  });
};

const runDetection = async (event) => {
  const alerts = [];
  
  const uploadAlert = await detectMaliciousFileUpload(event);
  if (uploadAlert) {
    alerts.push(uploadAlert);
  }
  
  return alerts;
};

module.exports = {
  runDetection
};