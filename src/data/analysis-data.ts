export type Confidence = "low" | "medium" | "high" | "critical";
export type TriageVerdict = "likely_vulnerable" | "needs_review" | "likely_false_positive";
export type VerificationStatus = "pending" | "confirmed_vulnerable" | "confirmed_safe" | "in_progress";

export interface LLMPass1Hypothesis {
  vulnerable: boolean;
  cwe_guess?: string;
  reasoning: string;
  confidence: Confidence;
}

export interface LLMPass2Triage {
  verdict: TriageVerdict;
  explanation: string;
  recommendation: string;
  status: VerificationStatus;
}

export interface VulnerabilityFinding {
  pass1_hypothesis: LLMPass1Hypothesis;
  pass2_triage: LLMPass2Triage;
}

export interface FunctionNode {
  id: string;
  name: string;
  filePath: string;
  sourceCode: string;
  startLine: number;
  endLine: number;
  vulnerability?: VulnerabilityFinding;
}

export interface CallEdge {
  source: string; // function id
  target: string; // function id
}

export interface CallGraph {
  nodes: FunctionNode[];
  edges: CallEdge[];
}

export const analysisData: CallGraph = {
  nodes: [
    {
      id: "f1",
      name: "userRegistration",
      filePath: "server/routes/users.ts",
      startLine: 42,
      endLine: 88,
      sourceCode: `
function userRegistration(req, res, next) {
  const email = req.body.email || '';
  const password = req.body.password || '';
  const passwordRepeat = req.body.passwordRepeat || '';
  if (email.length === 0) {
    return res.status(400).send('Email is required.');
  }
  if (password !== passwordRepeat) {
    return res.status(400).send('Passwords do not match.');
  }
  const user = {
    email: email,
    password: security.hash(password)
  };
  db.users.insert(user, (err, newUser) => {
    if (err) {
      return res.status(500).send('Failed to create user.');
    }
    res.status(201).send({ user: newUser });
  });
}
      `,
      vulnerability: {
        pass1_hypothesis: {
          vulnerable: true,
          cwe_guess: "CWE-79",
          reasoning: "The user's email is taken from the request body and included in the response without sanitization, which could lead to a reflected Cross-Site Scripting (XSS) vulnerability if an error message including the email is ever implemented.",
          confidence: "medium",
        },
        pass2_triage: {
          verdict: "needs_review",
          explanation: "The hypothesis is plausible. While the current code doesn't reflect the email back to the user, a future change that adds an error message like 'User with email xxx already exists' could introduce a vulnerability. The core issue is the lack of input validation on the email field.",
          recommendation: "Review the user creation and error handling logic. Implement strict input validation and output encoding for the email field. Manually test by attempting to register a user with a malicious email string.",
          status: "pending",
        },
      },
    },
    {
      id: "f2",
      name: "getProductDetails",
      filePath: "server/routes/products.ts",
      startLine: 120,
      endLine: 135,
      sourceCode: `
function getProductDetails(req, res, next) {
  const productId = req.params.id;
  db.products.findOne({ _id: productId }, (err, product) => {
    if (err || !product) {
      return res.status(404).send('Product not found.');
    }
    res.render('product_details', { product: product });
  });
}
      `,
    },
    {
      id: "f3",
      name: "searchProducts",
      filePath: "server/routes/search.ts",
      startLine: 25,
      endLine: 45,
      sourceCode: `
function searchProducts(req, res, next) {
  const query = req.query.q;
  const sql = "SELECT * FROM Products WHERE name LIKE '%" + query + "%' AND deletedAt IS NULL";
  db.sequelize.query(sql).then(([results, metadata]) => {
    res.status(200).json({ data: results });
  }).catch(err => {
    res.status(500).send(err.message);
  })
}
      `,
      vulnerability: {
        pass1_hypothesis: {
          vulnerable: true,
          cwe_guess: "CWE-89",
          reasoning: "The search query parameter 'q' is directly concatenated into a raw SQL query. This is a classic SQL Injection vulnerability. An attacker could manipulate the query to bypass authentication, exfiltrate data, or corrupt the database.",
          confidence: "critical",
        },
        pass2_triage: {
          verdict: "likely_vulnerable",
          explanation: "The model's reasoning is correct. The code directly concatenates user input into an SQL query, which is a textbook example of SQL Injection. There are no apparent sanitization or parameterization mechanisms in place.",
          recommendation: "This is a high-priority finding. The query must be rewritten using parameterized statements (prepared statements) to prevent injection attacks. The developer should immediately fix this.",
          status: "pending",
        },
      },
    },
    {
        id: "f4",
        name: "redirect",
        filePath: "server/routes/redirect.ts",
        startLine: 15,
        endLine: 22,
        sourceCode: \`
  router.get('/', (req, res, next) => {
    const targetUrl = req.query.to
    if (utils.isUrlToRedirect(targetUrl)) {
      res.redirect(targetUrl)
    } else {
      res.status(400).send('Invalid redirect URL.')
    }
  })\`,
        vulnerability: {
          pass1_hypothesis: {
            vulnerable: true,
            cwe_guess: "CWE-601",
            reasoning: "The application redirects to a URL specified in the 'to' query parameter. If the validation in 'isUrlToRedirect' is insufficient, an attacker could craft a malicious URL to redirect users to a phishing site.",
            confidence: "high",
          },
          pass2_triage: {
            verdict: "likely_vulnerable",
            explanation: "The security of this redirect depends entirely on the implementation of 'isUrlToRedirect'. Given the context of a deliberately vulnerable application, this validation is likely flawed. This pattern is a common source of Open Redirect vulnerabilities.",
            recommendation: "Manually investigate the 'isUrlToRedirect' function to determine if its validation can be bypassed. A safe implementation would involve a whitelist of allowed redirect targets.",
            status: "in_progress",
          },
        },
      },
      {
        id: "f5",
        name: "profileImage",
        filePath: "server/routes/profile.ts",
        startLine: 50,
        endLine: 65,
        sourceCode: \`
  router.post('/api/profile/image', (req, res, next) => {
    const userId = req.user.id;
    const imageUrl = req.body.imageUrl;
    // The application fetches the image from the URL and displays it on the profile.
    // This could be a vector for SSRF if the URL is not validated.
    db.users.update({ _id: userId }, { $set: { profileImage: imageUrl }})
      .then(() => {
        res.status(200).send('Profile image updated.');
      })
      .catch(err => {
        res.status(500).send(err.message);
      })
  })\`,
        vulnerability: {
          pass1_hypothesis: {
            vulnerable: true,
            cwe_guess: "CWE-918",
            reasoning: "The application accepts a URL for a profile image and likely fetches it server-side. If an attacker provides an internal URL (e.g., http://169.254.169.254/latest/meta-data/), they could perform a Server-Side Request Forgery (SSRF) attack to access internal services or cloud metadata.",
            confidence: "high",
          },
          pass2_triage: {
            verdict: "needs_review",
            explanation: "The hypothesis of SSRF is strong, but depends on whether the application actually fetches the image server-side upon update, or if it's just stored and rendered client-side. If it's fetched by the server, this is a critical vulnerability.",
            recommendation: "Determine how the profile image URL is used. If the server makes a request to the provided URL, attempt to provide an internal or sensitive address to confirm the SSRF vulnerability. The fix would involve strict validation of the URL or fetching it through a proxy that blocks internal addresses.",
            status: "pending",
          },
        },
      }
  ],
  edges: [
    { source: "f1", target: "f2" }, // userRegistration might lead to product page
    { source: "f2", target: "f3" }, // product details might have a search feature
    { source: "f4", target: "f1" }, // A redirect might lead to the registration page
  ],
};
