// server  for now we use the inner memory , after this you can use database
// what this file do ,,,, authentication and credential
const express = require("express");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  generateAuthenticationOptions
} = require("@simplewebauthn/server");

const PORT = 3000;
const app = express();
// a public directry for client side code
app.use(express.static("./public"));
app.use(express.json());

const userStore = {};
const challengeStore = {};

app.post("/register", (req, res) => {
  console.log(req.body);

  const { username, password } = req.body;
  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password,
  };

  userStore[id] = user;
  console.log("register success fully ", user);

//   console.log("line 32 ", userStore);
  return res.json({ id });
});
app.post("/register-challenge", async (req, res) => {
  console.log(" /register api work", req.body);
  const { userId } = req.body;
  if (!userId) return res.status(404).json({ error: "user not found!!!!" });

  const user = userStore[userId];
//   console.log("line 32 ", userStore);
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "My cloud Machine",
    userName: user.username,
  });
  challengeStore[userId] = challengePayload.challenge;
//   console.log("line 48 ", challengeStore);
  return res.json({ option: challengePayload });
});

app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;
  if (!userId) return res.status(404).json({ error: "user not found!!!!" });

  const user = userStore[userId];
  const challenge = challengeStore[userId];
//   console.log("line 58 ", challengeStore);

  const verificatoinResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedRPID: "passkeyauthentication.onrender.com",
    expectedOrigin: "https://passkeyauthentication.onrender.com",
    response: cred,
  });

  if (!verificatoinResult.verified)
    return res.json({ error: "could not verify" });
  userStore[userId].passkey = verificatoinResult.registrationInfo;

  return res.json({ verified: "ture" });

});

//   login using passkey 1.create the challenge on server side and send to clinet on call

  app.post("/login-challenge", async (req, res) => {
    console.log("api called");
    const { userId } = req.body;

    if (!userStore[userId])
      return res.status(404).json({ error: " user not found" });

    const opts = await generateAuthenticationOptions({
      rpID: "localhost",
    });

    console.log("api called");

    challengeStore[userId] = opts.challenge; // opts is type of challenge
    return res.json({ option: opts }), console.log("api called");
    

  });

  app.post('/login-verify',async(req,res)=>{
    const {userId,cred} = req.body
    if(!userStore[userId]) return res.status(404).json({error: ' user not found'})

    const user = userStore[userId]
    const challenge = challengeStore[userId];

    console.log('user',user,"userId",userId);
    console.log("user.passkey.credential.publicKey",user.passkey.credential.publicKey);
    console.log('user.passkey.credential.id', user.passkey.credential.id);
    console.log('user.passkey.credential.counter', user.passkey.credential.counter);


    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin:'https://passkeyauthentication.onrender.com',
        expectedRPID:'passkeyauthentication.onrender.com',
        response: cred,
        credential: {
          id:user.passkey.credential.id,
          publicKey: user.passkey.credential.publicKey,
          counter: user.passkey.credential.counter,
          transports: user.passkey.credential.transports,
        },
        // authenticator:user.passkey
    })

    if(!result.verified) return res.json({error:'something went wrong'})

    // login the user
    return res.json({success: "userVerified", userId})
  })

app.listen(PORT, () => {
  console.log("server is running at PORT 3000");
});
