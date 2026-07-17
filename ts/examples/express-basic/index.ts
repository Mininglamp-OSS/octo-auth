/**
 * examples/express-basic — minimal usage example.
 *
 * Does NOT need to run; `tsc --noEmit` type-checks it. Demonstrates:
 *   - newFullMultiVerifier construction from Config
 *   - expressMiddleware factory + spaceHeader fallback
 *   - typed access to req.principal via the ambient types-ext augmentation
 *
 * To run, `npm install express` in this directory and then:
 *   OCTO_SERVER_URL=... npx tsx examples/express-basic/index.ts
 */

import express from 'express'
import { newFullMultiVerifier } from '../../src/index.js'
import { expressMiddleware } from '../../src/middleware/express.js'

const baseUrl = process.env['OCTO_SERVER_URL']
if (!baseUrl) {
  throw new Error('set OCTO_SERVER_URL to run this example')
}

const verifier = newFullMultiVerifier({ baseUrl })

const app = express()

app.use(
  expressMiddleware({
    verifier,
    spaceHeader: 'X-Space-Id',
  }),
)

app.get('/hello', (req, res) => {
  // req.principal is typed as Principal | undefined via types-ext.d.ts.
  const p = req.principal
  if (!p) {
    res.status(500).send('unreachable: middleware should have set principal')
    return
  }
  res.json({
    kind: p.kind,
    uid: p.uid,
    spaceId: p.spaceId,
  })
})

const port = Number(process.env['PORT']) || 8080
app.listen(port, () => {
  console.log(`example listening on :${port}`)
})
