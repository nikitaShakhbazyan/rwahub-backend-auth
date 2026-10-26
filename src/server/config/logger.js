const getLogger = require('glogg');
const path = require('path');
const fs = require('fs');
const util = require('util');

const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const LEVEL_ORDER = {
  debug: 0,
  http: 1,
  info: 1,
  warn: 2,
  error: 3
};

const minLevel = LEVEL_ORDER[process.env.LOG_LEVEL] ?? LEVEL_ORDER.info;
const logger = getLogger('rwahub-backend');

function shouldLog(level) {
  return (LEVEL_ORDER[level] ?? LEVEL_ORDER.info) >= minLevel;
}

function stringifyPayload(payload) {
  if (payload instanceof Error) {
    return payload.stack || payload.message;
  }
  if (typeof payload === 'string') {
    return payload;
  }
  try {
    return JSON.stringify(payload);
  } catch (_error) {
    return util.inspect(payload);
  }
}

function formatLine(level, message) {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  return `${timestamp} [${level}] ${message}`;
}

function appendLog(filename, line) {
  fs.appendFile(path.join(logsDir, filename), `${line}\n`, () => {});
}

function writeLog(level, message, files) {
  if (!shouldLog(level)) {
    return;
  }

  const line = formatLine(level, stringifyPayload(message));
  if (process.env.NODE_ENV !== 'production') {
    if (level === 'error') {
      console.error(line);
    } else if (level === 'warn') {
      console.warn(line);
    } else {
      console.log(line);
    }
  }

  files.forEach((filename) => appendLog(filename, line));
}

logger.on('debug', (message) => {
  writeLog('debug', message, ['combined.log']);
});

logger.on('info', (message) => {
  writeLog('info', message, ['combined.log']);
});

logger.on('warn', (message) => {
  writeLog('warn', message, ['combined.log']);
});

logger.on('error', (message) => {
  writeLog('error', message, ['error.log', 'combined.log']);
});

logger.http = (message, meta) => {
  const payload = meta ? `${message} ${stringifyPayload(meta)}` : message;
  writeLog('http', payload, ['access.log', 'combined.log']);
};

process.on('uncaughtException', (err) => {
  const message = err.stack || err.message;
  appendLog('exceptions.log', formatLine('error', message));
  logger.error('uncaughtException %s', message);
});

process.on('unhandledRejection', (reason) => {
  const message = reason instanceof Error
    ? (reason.stack || reason.message)
    : stringifyPayload(reason);
  appendLog('rejections.log', formatLine('error', message));
  logger.error('unhandledRejection %s', message);
});

const requestLogger = (req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    logger.http('HTTP Request', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${Date.now() - start}ms`,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      userId: req.user?.userId || 'anonymous',
      requestId: req.id
    });
  });

  next();
};

const errorLogger = (err, req, res, next) => {
  logger.error('Request Error %s', stringifyPayload({
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userId: req.user?.userId || 'anonymous',
    requestId: req.id,
    userAgent: req.get('User-Agent')
  }));
  next(err);
};

function withMeta(prefix, message, meta, level = 'info') {
  const text = meta && Object.keys(meta).length > 0
    ? `${prefix} ${message} ${stringifyPayload(meta)}`
    : `${prefix} ${message}`;
  logger[level](text);
}

const loggers = {
  api: (message, meta = {}) => withMeta('[API]', message, meta),
  database: (message, meta = {}) => withMeta('[DATABASE]', message, meta),
  auth: (message, meta = {}) => withMeta('[AUTH]', message, meta),
  transaction: (message, meta = {}) => withMeta('[TRANSACTION]', message, meta),
  upload: (message, meta = {}) => withMeta('[UPLOAD]', message, meta),
  security: (message, meta = {}) => withMeta('[SECURITY]', message, meta, 'warn'),
  performance: (message, meta = {}) => withMeta('[PERFORMANCE]', message, meta),
  business: (message, meta = {}) => withMeta('[BUSINESS]', message, meta)
};

const rotateLogs = () => {
  const logFiles = [
    'error.log',
    'combined.log',
    'access.log',
    'exceptions.log',
    'rejections.log'
  ];

  logFiles.forEach((filename) => {
    const filePath = path.join(logsDir, filename);
    if (!fs.existsSync(filePath)) {
      return;
    }

    const fileSizeInMB = fs.statSync(filePath).size / (1024 * 1024);
    if (fileSizeInMB > 5) {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const rotatedFilename = `${filename}.${timestamp}`;
      fs.renameSync(filePath, path.join(logsDir, rotatedFilename));
      logger.info('Log file rotated: %s -> %s', filename, rotatedFilename);
    }
  });
};

const rotationTimer = setInterval(rotateLogs, 24 * 60 * 60 * 1000);
rotationTimer.unref();

module.exports = {
  logger,
  requestLogger,
  errorLogger,
  loggers,
  rotateLogs
};
