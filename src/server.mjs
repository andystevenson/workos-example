import express from 'express'
import { WorkOS } from '@workos-inc/node'
// Javascript Object Signing and Encryption (JOSE)
// https://www.npmjs.com/package/jose
import { SignJWT } from 'jose'
import cookieParser from 'cookie-parser'

const app = express()
app.use(cookieParser())
const workos = new WorkOS(process.env.WORKOS_API_KEY)
const clientId = process.env.WORKOS_CLIENT_ID

app.get('/auth', (_req, res) => {
  const authorizationUrl = workos.userManagement.getAuthorizationUrl({
    // Specify that we'd like AuthKit to handle the authentication flow
    provider: 'authkit',

    // The callback URI AuthKit will redirect to after authentication
    redirectUri: 'http://localhost:3000/callback',
    clientId,
  })

  // Redirect the user to the AuthKit sign-in page
  res.redirect(authorizationUrl)
})

// Get secret
const secret = new Uint8Array(Buffer.from(process.env.JWT_SECRET_KEY, 'base64'))

app.get('/callback', async (req, res) => {
  // The authorization code returned by AuthKit
  const code = String(req.query.code)

  const { user } = await workos.userManagement.authenticateWithCode({
    code,
    clientId,
  })

  // Create a JWT with the user's information
  const token = await new SignJWT({
    // Here you might lookup and retrieve user details from your database
    user,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret)

  // Store in a cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
  })

  // Redirect the user to the homepage
  res.redirect('/')
})

app.get('/user', async (req, res) => {
  const token = req.cookies.token

  // Verify the JWT signature
  let verifiedToken
  try {
    verifiedToken = await jwtVerify(token, secret)
  } catch {
    return res.status(401).send({ isAuthenticated: false })
  }

  // Return the User object if the token is valid
  res.status(200).send({
    isAuthenticated: true,
    user: verifiedToken.payload.user,
  })
})

const port = 3000

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example workos app listening on port ${port}`)
})

//////////////////
