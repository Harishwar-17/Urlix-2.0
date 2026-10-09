import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { analyzeUrl, defangUrl, refangUrl, extractUrlsFromText } from './src/engine/analyzer.ts'

const startTime = Date.now()

function urlixApiPlugin(): Plugin {
  return {
    name: 'urlix-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith('/api/')) {
          return next()
        }

        const url = new URL(req.url, 'http://localhost:3000')

        if (req.method === 'GET' && url.pathname === '/api/health') {
          res.setHeader('Content-Type', 'application/json')
          res.setHeader('Access-Control-Allow-Origin', '*')
          res.statusCode = 200
          res.end(
            JSON.stringify({
              status: 'healthy',
              service: 'URLIX Detection Engine',
              tagline: 'See the Link. Spot the Threat.',
              version: '0.3.0',
              timestamp: new Date().toISOString(),
              uptime_seconds: Math.round((Date.now() - startTime) / 1000),
              environment: 'development',
              detection_engine: 'active_milestone_3',
            })
          )
          return
        }

        if (req.method === 'POST' && url.pathname === '/api/analyze') {
          let body = ''
          req.on('data', (chunk) => {
            body += chunk
          })
          req.on('end', () => {
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
            try {
              const data = body ? JSON.parse(body) : {}
              const inputUrl = (data.url || '').trim()

              if (!inputUrl) {
                res.statusCode = 400
                res.end(
                  JSON.stringify({
                    detail: 'URL parameter is required and cannot be empty.',
                  })
                )
                return
              }

              const result = analyzeUrl(inputUrl)
              res.statusCode = 200
              res.end(JSON.stringify(result))
            } catch (err: any) {
              res.statusCode = 400
              res.end(
                JSON.stringify({
                  detail: err.message || 'Malformed or invalid URL syntax.',
                })
              )
            }
          })
          return
        }

        if (req.method === 'POST' && url.pathname === '/api/analyze/bulk') {
          let body = ''
          req.on('data', (chunk) => {
            body += chunk
          })
          req.on('end', () => {
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
            try {
              const data = body ? JSON.parse(body) : {}
              const rawUrls: string[] = Array.isArray(data.urls)
                ? data.urls
                : extractUrlsFromText(data.text || '')

              const results = []
              for (const u of rawUrls.slice(0, 50)) {
                try {
                  results.push(analyzeUrl(u))
                } catch {
                  // ignore malformed items in bulk
                }
              }

              res.statusCode = 200
              res.end(
                JSON.stringify({
                  total_submitted: rawUrls.length,
                  total_analyzed: results.length,
                  results,
                })
              )
            } catch (err: any) {
              res.statusCode = 400
              res.end(
                JSON.stringify({
                  detail: err.message || 'Bulk analysis error.',
                })
              )
            }
          })
          return
        }

        if (req.method === 'POST' && url.pathname === '/api/defang') {
          let body = ''
          req.on('data', (chunk) => {
            body += chunk
          })
          req.on('end', () => {
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
            try {
              const data = body ? JSON.parse(body) : {}
              const target = data.url || ''
              res.statusCode = 200
              res.end(
                JSON.stringify({
                  defanged: defangUrl(target),
                  refanged: refangUrl(target),
                })
              )
            } catch (err: any) {
              res.statusCode = 400
              res.end(JSON.stringify({ detail: err.message }))
            }
          })
          return
        }

        next()
      })
    },
    configurePreviewServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith('/api/')) {
          return next()
        }

        const url = new URL(req.url, 'http://localhost:3000')

        if (req.method === 'GET' && url.pathname === '/api/health') {
          res.setHeader('Content-Type', 'application/json')
          res.setHeader('Access-Control-Allow-Origin', '*')
          res.statusCode = 200
          res.end(
            JSON.stringify({
              status: 'healthy',
              service: 'URLIX Detection Engine',
              tagline: 'See the Link. Spot the Threat.',
              version: '0.3.0',
              timestamp: new Date().toISOString(),
              uptime_seconds: Math.round((Date.now() - startTime) / 1000),
              environment: 'production',
              detection_engine: 'active_milestone_3',
            })
          )
          return
        }

        if (req.method === 'POST' && url.pathname === '/api/analyze') {
          let body = ''
          req.on('data', (chunk) => {
            body += chunk
          })
          req.on('end', () => {
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
            try {
              const data = body ? JSON.parse(body) : {}
              const inputUrl = (data.url || '').trim()

              if (!inputUrl) {
                res.statusCode = 400
                res.end(
                  JSON.stringify({
                    detail: 'URL parameter is required and cannot be empty.',
                  })
                )
                return
              }

              const result = analyzeUrl(inputUrl)
              res.statusCode = 200
              res.end(JSON.stringify(result))
            } catch (err: any) {
              res.statusCode = 400
              res.end(
                JSON.stringify({
                  detail: err.message || 'Malformed or invalid URL syntax.',
                })
              )
            }
          })
          return
        }

        next()
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    urlixApiPlugin(),
    react(),
    tailwindcss(),
  ],
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  preview: {
    port: 3000,
    host: '0.0.0.0',
  },
})
