import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const port = 3000;

async function startServer() {
  const app = express();
  app.use(express.json());

  // Initialize server-side Gemini client
  const apiKey = process.env.GEMINI_API_KEY;
  const ai = new GoogleGenAI({
    apiKey: apiKey || '',
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  // Verify key logs
  if (!apiKey) {
    console.warn("WARNING: GEMINI_API_KEY environment variable is not set. Real AI analysis will fail until set.");
  }

  // API Route: Phishing and Scam Analyzer
  app.post('/api/phishing-analyzer', async (req, res) => {
    try {
      const { content, sourceUrl, contextType } = req.body;
      if (!content) {
        res.status(400).json({ error: "Content is required for security threat analysis." });
        return;
      }

      if (!apiKey) {
        // Fallback simulated model response when API key is missing to prevent crash
        res.json(getSimulatedPhishingResponse(content, contextType));
        return;
      }

      const prompt = `Analyze the following communication content for potential cybersecurity threats, scam indicators, social engineering hooks, phishing flags, and transaction risks.
Context Type of content: ${contextType || 'General text/link'}
Source URL or sender info (if provided): ${sourceUrl || 'Unknown source'}

Content to evaluate:
---
${content}
---`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are AegisX Cyber Security Threat Analyzer, a state-of-the-art predictive cybersecurity machine learning intelligence. You evaluate code snippets, emails, texts, messages, URLs, or transaction states, scoring them rigorously and compiling bulletproof defensive remediation. Return parsed, objective insights.",
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              threatScore: { type: Type.INTEGER, description: "Defensive threat score indexing vulnerability level from 0 (completely benign) to 100 (hostile/lethal attack)." },
              riskTier: { type: Type.STRING, description: "Security Risk evaluation: SAFE, SUSPICIOUS, or CRITICAL." },
              threatType: { type: Type.STRING, description: "Type of threat detected (e.g., Phishing Attack, SMS Fraud, Suspicious Link, Invoice Scam, Normal Email, Identity Harvesting)." },
              riskSummary: { type: Type.STRING, description: "A simple, non-technical sentence explaining why this was flagged or designated with this risk classification." },
              redFlags: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Key tactical red flags triggered (e.g. artificial urgency, domain spelling errors, suspicious requests for sensitive tokens, unauthenticated bank links)."
              },
              actionableAdvice: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Immediate step-by-step defensive safety directives for the end-user."
              },
              educationalConcept: { type: Type.STRING, description: "Brief educational tip explaining the social engineering or exploitation tactic detected." }
            },
            required: ["threatScore", "riskTier", "threatType", "riskSummary", "redFlags", "actionableAdvice", "educationalConcept"]
          }
        }
      });

      if (response && response.text) {
        const jsonResult = JSON.parse(response.text.trim());
        res.json(jsonResult);
      } else {
        throw new Error("Empty response received from the model");
      }
    } catch (error: any) {
      console.error("Phishing analyzer error:", error);
      res.status(500).json({
        error: "Threat analysis server exception, employing secure local fallback simulation mode fallback.",
        details: error.message,
        fallbackData: getSimulatedPhishingResponse(req.body.content || "", req.body.contextType || "SMS")
      });
    }
  });

  // API Route: Deepfake and Voice Scam Analyzer
  app.post('/api/deepfake-analyzer', async (req, res) => {
    try {
      const { description, dialogueTranscript, callerToneInfo } = req.body;
      const content = dialogueTranscript || description;

      if (!content) {
        res.status(400).json({ error: "Context description or dialogue transcript is required." });
        return;
      }

      if (!apiKey) {
        res.json(getSimulatedDeepfakeResponse(content));
        return;
      }

      const prompt = `Assess the following caller behavior, spoken transcript, or deepfake narrative for characteristics of synthetic voice cloning, dynamic AI video manipulation, conversational pressure, and coercive social scams.
Caller details / Tone overview: ${callerToneInfo || "Not specified / robotic or panicked"}
Transcript or details to evaluate:
---
${content}
---`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are the AegisX Deepfake & Voice Scam Detection expert. You specialized in auditing synthesized voices, facial mapping defects, artificial emotion replication, and coercion scripts (like fake ransom, grandparent scam overlays, impersonation of authority figures like Federal agents or bank fraud operators).",
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              deepfakeProbability: { type: Type.INTEGER, description: "Calculated risk percentage of audio cloning or video deepfake synthesis, from 0 to 100." },
              cloningIndicators: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Concrete synthesising or technical clone artifacts identified in speech rhythm or tone descriptions (gaps, metallic clicks, hyper-realistic distress overlays)."
              },
              scamLikelihood: { type: Type.STRING, description: "The degree of fraudulent coercion found: HIGH, MEDIUM, or LOW." },
              coercionTacticsSpotted: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Spotted psychological leverage handles (e.g. forced immediate payment via nontraceable wires/giftcards, isolation directives, fake distress states)."
              },
              verificationCountersteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Tactical questions or protocols the user should deploy (e.g., custom family passphrase check, hanging up and calling verified channels directly)."
              }
            },
            required: ["deepfakeProbability", "cloningIndicators", "scamLikelihood", "coercionTacticsSpotted", "verificationCountersteps"]
          }
        }
      });

      if (response && response.text) {
        res.json(JSON.parse(response.text.trim()));
      } else {
        throw new Error("Empty response received from deepfake model");
      }
    } catch (error: any) {
      console.error("Deepfake analyzer error:", error);
      res.status(500).json({
        error: "Deepfake synthesis auditing server exception.",
        details: error.message,
        fallbackData: getSimulatedDeepfakeResponse(req.body.dialogueTranscript || req.body.description || "")
      });
    }
  });

  // API Route: Digital Identity Dark Web Scanner
  app.post('/api/leak-scanner', async (req, res) => {
    try {
      const { targetHandle, handleType } = req.body; // e.g., email / phone / gamename
      if (!targetHandle) {
        res.status(400).json({ error: "Target address or identifier is required for identity breach audits." });
        return;
      }

      if (!apiKey) {
        res.json(getSimulatedLeakResponse(targetHandle, handleType || "email"));
        return;
      }

      const prompt = `Simulate an intelligence Dark Web search report assessing the compromised identity exposures for the following credential/handle:
Identifier Target: ${targetHandle}
Identifier Class: ${handleType || 'email'}

Provide a highly realistic status dashboard and past breach compromises, showing how this identifier classification is vulnerable. Combine general open-source data risks with predictive intelligence advice.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are the AegisX Dark Web Identity Scanner. You formulate realistic and educational breach assessments to alert users to past compromised databases, password leaks, credential stuffing pools, and active tracking matrices. Always generate realistic-looking mock compromises representing past famous databases combined with general cybersecurity knowledge.",
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              exposureSeverity: { type: Type.STRING, description: "Status rating: SECURE, LOW, MODERATE, or CRITICAL." },
              breachesSpotted: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    breachName: { type: Type.STRING, description: "Source of the database exposure (e.g., Global E-Commerce MegaBreach, Social Platform Leak, Telecom Carrier leak)." },
                    date: { type: Type.STRING, description: "Approximate historical date of breach." },
                    compromisedData: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Types of assets exposed (e.g., Sign-In Passwords, IP coordinates, SSN components, phone metadata)." }
                  },
                  required: ["breachName", "date", "compromisedData"]
                }
              },
              darkWebPrevalence: { type: Type.INTEGER, description: "Simulated score from 0 to 100 representing dark web hacker listing index." },
              securityRecommendations: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Defense directives specific to resolving compromised status (e.g. rotated authorization codes, hardware security keys, salt hashing configurations)."
              }
            },
            required: ["exposureSeverity", "breachesSpotted", "darkWebPrevalence", "securityRecommendations"]
          }
        }
      });

      if (response && response.text) {
        res.json(JSON.parse(response.text.trim()));
      } else {
        throw new Error("Empty response from breach model");
      }
    } catch (error: any) {
      console.error("Leak scan exception:", error);
      res.status(500).json({
        error: "Dark Web monitoring server timeout.",
        details: error.message,
        fallbackData: getSimulatedLeakResponse(req.body.targetHandle || "user@example.com", req.body.handleType || "email")
      });
    }
  });

  // API Route: Digital Twin Chat Companion
  app.post('/api/twin-chat', async (req, res) => {
    try {
      const { message, history, twinProfile } = req.body;
      if (!message) {
        res.status(400).json({ error: "Message is required." });
        return;
      }

      const profile = twinProfile || {
         age: "30",
         occupation: "Professional",
         techSavviness: "Medium",
         devices: "iPhone, Mac, Chrome browser",
         concerns: "Identity theft, fake URLs, scam calls"
      };

      if (!apiKey) {
        // Simple chat simulation fallback
        const responseText = `I am AegisX Twin [Offline Mode]. I have received your message: "${message}". Your digital twin parameters (Occupation: ${profile.occupation}, Concerns: ${profile.concerns}) are registered! In offline mode I highly recommend configuring proper verification codes, checking sender domain details meticulously, and never inputting payment tokens in unauthorized fields.`;
        res.json({ response: responseText });
        return;
      }

      // Reconstruct simple turn context for conversation
      const promptHistory = history ? history.map((h: any) => `${h.role === 'user' ? 'User' : 'AegisX Twin'}: ${h.content}`).join('\n') : "";
      
      const fullPrompt = `${promptHistory}\nUser: ${message}`;

      const systemInstruction = `You are AegisX Autonomous Digital Twin, a friendly, hyper-vigilant personal cybersecurity guardian created to safeguard the client from modern technological exploits.
The user is a ${profile.age}-year-old ${profile.occupation} with ${profile.techSavviness} tech savviness level.
Their primary setup is running: ${profile.devices}.
They are most concerned about: ${profile.concerns}.

Your personality is protective, highly intelligent, technically exact, but highly friendly. Avoid complex computing jargon if the user has low savviness. Frame yourself as their virtual digital carbon copy that monitors threats and gives friendly preventive tips so details never get stolen. Provide brief, highly actionable security answers.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: fullPrompt,
        config: {
          systemInstruction,
          temperature: 0.7,
        }
      });

      if (response && response.text) {
        res.json({ response: response.text.trim() });
      } else {
        res.json({ response: "I did not receive context back from the digital core. Ensure your settings are compliant and let's try again!" });
      }
    } catch (error: any) {
      console.error("Twin Chat Error:", error);
      res.status(500).json({
        error: "Dynamic communication loop failed.",
        details: error.message,
        response: `[AegisX Shield Active] I had an error in my neural communications link but my security systems remain fully operational. Remember to always enable standard two-factor authentication, do not trust unexpected corporate text messages asking for rapid payments, and stay safe online!`
      });
    }
  });

  // Integration middleware for Vite and React Client serving
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("Vite development server connected.");
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
    console.log("Static client files serving routing enabled.");
  }

  app.listen(port, "0.0.0.0", () => {
    console.log(`AegisX server booted securely and running on http://0.0.0.0:${port}`);
  });
}

// Fallback generators to maintain pristine offline demonstration if key is missing or system limits are triggered:
function getSimulatedPhishingResponse(content: string, type: string) {
  const containsUrgent = /urgent|verify|suspend|limited|win|claim|bank|card|password|ssn|social/i.test(content);
  const containsUrl = /https?:\/\//.test(content);
  const containsSuspiciousDomain = /paypal-secure|verify-identity|alert-security|refund-now|login-update|support-[a-z0-9]+\./i.test(content);

  let threatScore = 15;
  let riskTier = "SAFE";
  let threatType = "General communication";
  let riskSummary = "No overt red flags found. The sender seems to be using general social dialogue.";
  let redFlags = ["None identified"];
  let actionableAdvice = ["Regular vigilance is sufficient.", "Do not click links if you eventually suspect the sender."];

  if (containsUrgent || containsUrl || containsSuspiciousDomain) {
    threatScore = containsSuspiciousDomain ? 92 : (containsUrgent && containsUrl ? 85 : 55);
    riskTier = threatScore > 80 ? "CRITICAL" : "SUSPICIOUS";
    threatType = type || "Phishing Scam Attempt";
    riskSummary = "Flagged due to artificial tactical pressure, unauthenticated call-to-actions, or suspicious link metrics.";
    redFlags = [];
    actionableAdvice = [];

    if (containsUrgent) {
      redFlags.push("Urgency Trap: Encourages immediate action to fix an arbitrary problem or lock status.");
      actionableAdvice.push("Do not respond or let tension hasten your decision-making.");
    }
    if (containsUrl) {
      redFlags.push("External Redirect: Content directs user to an external platform to enter details.");
      actionableAdvice.push("Audit the domain extension closely. Avoid signing in on redirect pages.");
    }
    if (containsSuspiciousDomain || threatScore > 75) {
      redFlags.push("Spoofed Domain: Links mimic official institutions but originate from unverified servers.");
      actionableAdvice.push("Completely close and discard this channel. Block the sender index.");
    }

    actionableAdvice.push("Contact the company via verified official phone directories if you feel it is legitimate.");
  }

  return {
    threatScore,
    riskTier,
    threatType,
    riskSummary,
    redFlags,
    actionableAdvice,
    educationalConcept: "Social engineering relies heavily on artificial emergency and impersonation to bypass critical cognitive friction."
  };
}

function getSimulatedDeepfakeResponse(content: string) {
  const containsMoney = /wire|crypto|gift\s*card|bank|account|cash|thousands|dollars/i.test(content);
  const containsKidnap = /accident|jail|emergency|hurt|kidnap|ransom|police|officer/i.test(content);

  let deepfakeProbability = 30;
  let scamLikelihood = "LOW";
  let cloningIndicators = ["Minor compression noise consistent with normal digital cellular routing."];
  let coercionTacticsSpotted = ["General contact structure."];
  let verificationCountersteps = ["Simply check Caller ID identity", "Ask for basic details to clarify context."];

  if (containsMoney || containsKidnap) {
    deepfakeProbability = containsKidnap ? 88 : 72;
    scamLikelihood = "HIGH";
    cloningIndicators = [
      "No natural background breath intervals in emotional distress dialogue.",
      "Slight metallic frequency fluctuation matching generative voice-synthesizing artifacts.",
      "Uncanny speed-matching cadence where speaker talks without pauses."
    ];
    coercionTacticsSpotted = [
      "Authority manipulation: mimicking law agents, technicians, or family members.",
      "High urgency bypass: forcing transaction parameters without allowing third-party consultation."
    ];
    verificationCountersteps = [
      "Immediately hang up and verify the subject through a pre-negotiated family safeword.",
      "Call the trusted contact directly on their secondary line or physical circle.",
      "Never buy gift cards, or make rapid crypto or wire transfers in response to voice orders."
    ];
  }

  return {
    deepfakeProbability,
    cloningIndicators,
    scamLikelihood,
    coercionTacticsSpotted,
    verificationCountersteps
  };
}

function getSimulatedLeakResponse(target: string, type: string) {
  let scoreOfPrevalence = Math.abs(target.length * 7) % 85 + 10;
  let exposureSeverity = scoreOfPrevalence > 75 ? "CRITICAL" : (scoreOfPrevalence > 40 ? "MODERATE" : "LOW");
  
  const simulatedBreaches = [
    {
      breachName: "Global Tech Services compromised vault",
      date: "May 2024",
      compromisedData: ["Passwords", "Username handle", "IP History logs"]
    },
    {
      breachName: "Major Retailer E-commerce leak",
      date: "November 2023",
      compromisedData: ["E-mail handle", "Mailing address", "Purchase records"]
    }
  ];

  if (scoreOfPrevalence < 30) {
    simulatedBreaches.pop();
  }

  return {
    exposureSeverity,
    breachesSpotted: simulatedBreaches,
    darkWebPrevalence: scoreOfPrevalence,
    securityRecommendations: [
      "Instate distinct password routines for every node. Avoid reuse.",
      "Activate Authenticator-based Two-Factor (2FA) immediately for this identifier index.",
      "Review connected sessions on Google and social media configuration panels."
    ]
  };
}

startServer();
