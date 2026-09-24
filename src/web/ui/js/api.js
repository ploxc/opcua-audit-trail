// Calls to the gateway's JSON API under /api.

import { render, state } from "./state.js";

/** An error response from the API; `status` is the HTTP status. */
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * Sends one request and returns the parsed JSON (or text) of the answer.
 * The X-Requested-With header is what the gateway's CSRF check asks for.
 * A 401 means the session ended: the login screen is shown.
 */
export async function api(method, path, body) {
  const options = {
    method,
    headers: { "X-Requested-With": "opcua-audit-gateway" },
    credentials: "same-origin",
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch("/api" + path, options);
  if (response.status === 401 && path !== "/login") {
    state.user = null;
    render();
    throw new ApiError(401, "Not logged in");
  }
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!response.ok) {
    throw new ApiError(response.status, (data && data.error) || response.statusText);
  }
  return data;
}

export const get = (path) => api("GET", path);
export const post = (path, body = {}) => api("POST", path, body);
export const put = (path, body) => api("PUT", path, body);
export const del = (path) => api("DELETE", path);
