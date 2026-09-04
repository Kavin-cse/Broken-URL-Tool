/**
 * @module logger
 * Structured logging with configurable verbosity.
 */

import chalk from 'chalk';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

let currentLevel: LogLevel = LogLevel.INFO;

/** Set the global log level */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

/** Set verbose mode (enables DEBUG level) */
export function setVerbose(verbose: boolean): void {
  currentLevel = verbose ? LogLevel.DEBUG : LogLevel.INFO;
}

function timestamp(): string {
  return new Date().toISOString().substring(11, 23);
}

/** Log a debug message (only shown in verbose mode) */
export function debug(message: string, ...args: unknown[]): void {
  if (currentLevel <= LogLevel.DEBUG) {
    console.log(chalk.gray(`[${timestamp()}] [DBG] ${message}`), ...args);
  }
}

/** Log an informational message */
export function info(message: string, ...args: unknown[]): void {
  if (currentLevel <= LogLevel.INFO) {
    console.log(chalk.blue(`[${timestamp()}] [INF] ${message}`), ...args);
  }
}

/** Log a warning message */
export function warn(message: string, ...args: unknown[]): void {
  if (currentLevel <= LogLevel.WARN) {
    console.log(chalk.yellow(`[${timestamp()}] [WRN] ${message}`), ...args);
  }
}

/** Log an error message */
export function error(message: string, ...args: unknown[]): void {
  if (currentLevel <= LogLevel.ERROR) {
    console.error(chalk.red(`[${timestamp()}] [ERR] ${message}`), ...args);
  }
}

/** Log a success message */
export function success(message: string, ...args: unknown[]): void {
  if (currentLevel <= LogLevel.INFO) {
    console.log(chalk.green(`[${timestamp()}] [OK]  ${message}`), ...args);
  }
}

export const logger = { debug, info, warn, error, success, setLogLevel, setVerbose };
