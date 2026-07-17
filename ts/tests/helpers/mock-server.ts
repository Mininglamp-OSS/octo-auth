/**
 * HTTP mock server helper. Mirrors Go's httptest.NewServer pattern using
 * node:http.createServer + .listen(0) to bind a random free port.
 *
 * Each test typically calls startMockServer(handler), gets { baseUrl, close,
 * requests }, exercises the SDK against baseUrl, then calls close().
 *
 * The `requests` array captures each incoming request (method, path, body,
 * headers) for assertions — useful for verifying include=context queries,
 * request-body payloads, and endpoint routing.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

/** Captured info about a single received request. */
export interface CapturedRequest {
  method: string
  path: string
  headers: Record<string, string | string[] | undefined>
  body: string
}

/** MockResponse describes what the handler wants to write. */
export interface MockResponse {
  status: number
  /** JSON string. If unset, the body is empty. */
  body?: string
  headers?: Record<string, string>
}

/**
 * MockHandler receives the captured request and returns the response the
 * mock server should send. It can also delay (return a promise that
 * resolves after a timeout) to simulate slow responses.
 */
export type MockHandler = (
  req: CapturedRequest,
) => MockResponse | Promise<MockResponse>

/** Handle returned by startMockServer. */
export interface MockServerHandle {
  baseUrl: string
  requests: CapturedRequest[]
  close: () => Promise<void>
}

/** Read the entire request body as a UTF-8 string. */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/**
 * startMockServer binds a HTTP server to a random localhost port and returns
 * a handle with baseUrl, request log, and close(). Every incoming request
 * is passed to `handler` for the response.
 */
export async function startMockServer(
  handler: MockHandler,
): Promise<MockServerHandle> {
  const captured: CapturedRequest[] = []
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const body = await readBody(req)
      const record: CapturedRequest = {
        method: req.method ?? 'GET',
        path: req.url ?? '/',
        headers: req.headers,
        body,
      }
      captured.push(record)
      const out = await handler(record)
      if (out.headers) {
        for (const [k, v] of Object.entries(out.headers)) {
          res.setHeader(k, v)
        }
      }
      if (!res.getHeader('content-type') && out.body !== undefined) {
        res.setHeader('Content-Type', 'application/json')
      }
      res.writeHead(out.status)
      if (out.body !== undefined) {
        res.end(out.body)
      } else {
        res.end()
      }
    } catch (err) {
      res.writeHead(500)
      res.end(String((err as Error).message))
    }
  })
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const addr = server.address() as AddressInfo
  const baseUrl = `http://127.0.0.1:${addr.port}`
  return {
    baseUrl,
    requests: captured,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()))
      }),
  }
}
