import Logger from "@classes/Utils/Logger";

/**
 * Logs structured audit events to stdout or a centralized logger
 */
export default function auditLogger({ logger = console } = {}) {
  return function logEvent({ action, userId, status = 'success', ip, meta = {} }) {
    Logger.info({
      type: 'iam_audit',
      timestamp: new Date().toISOString(),
      action,
      userId,
      status,
      ip,
      ...meta
    });
  };
}
