/* =====================================================
   VAULTGEN
   Password Generator + Credential Vault
===================================================== */

"use strict";


/* =====================================================
   CONSTANTS
===================================================== */

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()_+{}[]:;<>,.?/~";
const AMBIGUOUS = "Il1O0o|`'\"";

const STORAGE = {
  credentials: "vaultgen_credentials_v2",
  history: "vaultgen_history_v2",
  activity: "vaultgen_activity_v2"
};


/* =====================================================
   STATE
===================================================== */

let credentials = loadJSON(STORAGE.credentials, []);
let history = loadJSON(STORAGE.history, []);
let activities = loadJSON(STORAGE.activity, []);

let generatedPassword = "";

let passwordVisible = false;


/* =====================================================
   DOM HELPERS
===================================================== */

const $ = id => document.getElementById(id);

const passwordOutput = $("passwordOutput");
const lengthSlider = $("lengthSlider");
const lengthValue = $("lengthValue");

const strengthFill = $("strengthFill");
const strengthLabel = $("strengthLabel");

const entropyValue = $("entropyValue");
const crackTime = $("crackTime");

const vaultGrid = $("vaultGrid");

const toastContainer = $("toastContainer");


/* =====================================================
   STORAGE
===================================================== */

function loadJSON(key, fallback) {

  try {

    const value = localStorage.getItem(key);

    return value
      ? JSON.parse(value)
      : fallback;

  } catch (error) {

    console.error(error);

    return fallback;
  }
}


function saveJSON(key, value) {

  localStorage.setItem(
    key,
    JSON.stringify(value)
  );
}


/* =====================================================
   RANDOM HELPERS
===================================================== */

function secureRandom(max) {

  const array = new Uint32Array(1);

  crypto.getRandomValues(array);

  return array[0] % max;
}


function randomCharacter(chars) {

  return chars[
    secureRandom(chars.length)
  ];
}


function shuffleArray(array) {

  for (
    let i = array.length - 1;
    i > 0;
    i--
  ) {

    const j = secureRandom(i + 1);

    [
      array[i],
      array[j]
    ] = [
      array[j],
      array[i]
    ];
  }

  return array;
}


/* =====================================================
   PASSWORD GENERATOR
===================================================== */

function getSelectedSets() {

  let sets = [];

  if ($("uppercase").checked) {
    sets.push(
      removeAmbiguous(UPPER)
    );
  }

  if ($("lowercase").checked) {
    sets.push(
      removeAmbiguous(LOWER)
    );
  }

  if ($("numbers").checked) {
    sets.push(
      removeAmbiguous(NUMBERS)
    );
  }

  if ($("symbols").checked) {
    sets.push(
      removeAmbiguous(SYMBOLS)
    );
  }

  return sets.filter(Boolean);
}


function removeAmbiguous(chars) {

  if (!$("ambiguous").checked) {
    return chars;
  }

  return chars
    .split("")
    .filter(
      char =>
        !AMBIGUOUS.includes(char)
    )
    .join("");
}


function generatePassword(length = null) {

  let finalLength =
    length ||
    Number(lengthSlider.value);

  const sets = getSelectedSets();

  if (!sets.length) {

    showToast(
      "Select at least one character type."
    );

    return "";
  }

  if (finalLength < sets.length) {

    finalLength = sets.length;
  }

  let result = [];

  /* guarantee every selected character group */

  sets.forEach(set => {

    result.push(
      randomCharacter(set)
    );

  });


  let combined = sets.join("");

  while (
    result.length < finalLength
  ) {

    result.push(
      randomCharacter(combined)
    );
  }


  shuffleArray(result);

  return result.join("");
}


/* =====================================================
   PASSWORD ANALYSIS
===================================================== */

function calculateEntropy(password) {

  if (!password) {
    return 0;
  }

  let pool = 0;

  if (/[a-z]/.test(password)) {
    pool += 26;
  }

  if (/[A-Z]/.test(password)) {
    pool += 26;
  }

  if (/[0-9]/.test(password)) {
    pool += 10;
  }

  if (/[^a-zA-Z0-9]/.test(password)) {
    pool += 32;
  }

  return Math.round(
    password.length *
    Math.log2(
      Math.max(pool, 1)
    )
  );
}


function getPasswordScore(password) {

  if (!password) {
    return 0;
  }

  let score = 0;

  const entropy =
    calculateEntropy(password);


  if (password.length >= 12) {
    score += 20;
  }

  if (password.length >= 16) {
    score += 15;
  }

  if (password.length >= 20) {
    score += 10;
  }

  if (/[a-z]/.test(password)) {
    score += 10;
  }

  if (/[A-Z]/.test(password)) {
    score += 10;
  }

  if (/[0-9]/.test(password)) {
    score += 10;
  }

  if (/[^a-zA-Z0-9]/.test(password)) {
    score += 15;
  }

  if (entropy >= 70) {
    score += 10;
  }

  return Math.min(score, 100);
}


function getStrength(score) {

  if (score >= 85) {

    return {
      label: "Excellent",
      color: "#49d99b"
    };

  }

  if (score >= 70) {

    return {
      label: "Strong",
      color: "#65d5b0"
    };

  }

  if (score >= 50) {

    return {
      label: "Moderate",
      color: "#f4c95d"
    };

  }

  if (score >= 30) {

    return {
      label: "Weak",
      color: "#ff8b5c"
    };

  }

  return {
    label: "Very Weak",
    color: "#ff304f"
  };
}


function estimateCrackTime(entropy) {

  if (!entropy) {
    return "—";
  }

  if (entropy < 35) {
    return "Seconds";
  }

  if (entropy < 50) {
    return "Minutes";
  }

  if (entropy < 60) {
    return "Hours";
  }

  if (entropy < 70) {
    return "Days";
  }

  if (entropy < 80) {
    return "Years";
  }

  if (entropy < 100) {
    return "Centuries";
  }

  return "Extremely long";
}


/* =====================================================
   UPDATE PASSWORD UI
===================================================== */

function updatePasswordUI() {

  if (!generatedPassword) {
    return;
  }

  const score =
    getPasswordScore(
      generatedPassword
    );

  const entropy =
    calculateEntropy(
      generatedPassword
    );

  const strength =
    getStrength(score);


  passwordOutput.textContent =
    passwordVisible
      ? generatedPassword
      : "•".repeat(
          Math.min(
            generatedPassword.length,
            32
          )
        );


  strengthFill.style.width =
    `${score}%`;

  strengthFill.style.background =
    strength.color;

  strengthLabel.textContent =
    strength.label;

  strengthLabel.style.color =
    strength.color;


  entropyValue.textContent =
    `${entropy} bits`;

  crackTime.textContent =
    estimateCrackTime(entropy);


  updateChecklist(
    generatedPassword
  );

  updateAnalysis(
    generatedPassword
  );
}


/* =====================================================
   CHECKLIST
===================================================== */

function setCheck(id, valid) {

  const element = $(id);

  if (!element) {
    return;
  }

  const icon =
    element.querySelector("i");

  element.classList.toggle(
    "valid",
    valid
  );

  icon.className =
    valid
      ? "fa-solid fa-circle-check"
      : "fa-solid fa-circle-xmark";
}


function updateChecklist(password) {

  setCheck(
    "checkLength",
    password.length >= 12
  );

  setCheck(
    "checkUpper",
    /[A-Z]/.test(password)
  );

  setCheck(
    "checkNumber",
    /[0-9]/.test(password)
  );

  setCheck(
    "checkSymbol",
    /[^a-zA-Z0-9]/.test(password)
  );


  const unique =
    new Set(password.split("")).size;

  setCheck(
    "checkUnique",
    unique >= Math.min(
      10,
      password.length
    )
  );
}


/* =====================================================
   ANALYSIS RING
===================================================== */

function updateAnalysis(password) {

  const score =
    getPasswordScore(password);

  const circumference = 264;

  const offset =
    circumference -
    (score / 100) *
    circumference;

  $("analysisRing").style.strokeDashoffset =
    offset;

  $("analysisScore").textContent =
    score;


  const strength =
    getStrength(score);

  $("analysisStatus").textContent =
    strength.label;

  $("analysisStatus").style.color =
    strength.color;
}


/* =====================================================
   GENERATE
===================================================== */

function runGenerator() {

  generatedPassword =
    generatePassword();

  if (!generatedPassword) {
    return;
  }

  passwordVisible = false;

  history.unshift({
    password: generatedPassword,
    createdAt: Date.now()
  });

  history =
    history.slice(0, 30);

  saveJSON(
    STORAGE.history,
    history
  );

  updatePasswordUI();

  addActivity(
    "Password generated"
  );
}


/* =====================================================
   COPY
===================================================== */

async function copyText(text, message) {

  if (!text) {
    return;
  }

  try {

    await navigator.clipboard.writeText(
      text
    );

    showToast(
      message ||
      "Copied to clipboard."
    );

    addActivity(
      "Sensitive data copied to clipboard"
    );


    /*
      Auto-clear clipboard after 30 seconds.
      This is a convenience feature, not encryption.
    */

    setTimeout(
      async () => {

        try {

          await navigator.clipboard.writeText("");

        } catch (_) {}

      },
      30000
    );

  } catch (error) {

    showToast(
      "Clipboard permission was blocked."
    );
  }
}


/* =====================================================
   PASS PHRASE
===================================================== */

const WORDS = [
  "orbit",
  "pixel",
  "forest",
  "quantum",
  "river",
  "silver",
  "rocket",
  "matrix",
  "cloud",
  "falcon",
  "shadow",
  "signal",
  "winter",
  "vertex",
  "circuit",
  "ember",
  "neon",
  "ocean",
  "vector",
  "nova",
  "binary",
  "atlas",
  "delta",
  "cosmic",
  "echo",
  "fusion",
  "galaxy",
  "prism",
  "storm",
  "titan"
];


function generatePassphrase() {

  const words = [];

  for (let i = 0; i < 5; i++) {

    words.push(
      WORDS[
        secureRandom(
          WORDS.length
        )
      ]
    );
  }

  return words.join("-");
}


$("generatePassphrase")
  .addEventListener(
    "click",
    () => {

      const phrase =
        generatePassphrase();

      $("passphraseOutput")
        .textContent = phrase;

      copyText(
        phrase,
        "Passphrase generated."
      );

      addActivity(
        "Passphrase generated"
      );
    }
  );


/* =====================================================
   USERNAME GENERATOR
===================================================== */

const USER_WORDS = [
  "nova",
  "pixel",
  "code",
  "shadow",
  "byte",
  "orbit",
  "dev",
  "cloud",
  "matrix",
  "logic",
  "data",
  "cyber",
  "alpha",
  "vector",
  "quantum"
];


function generateUsername() {

  const word =
    USER_WORDS[
      secureRandom(
        USER_WORDS.length
      )
    ];

  const number =
    secureRandom(9999);

  return `${word}_${number}`;
}


$("generateUsername")
  .addEventListener(
    "click",
    () => {

      const username =
        generateUsername();

      $("usernameOutput")
        .textContent = username;

      copyText(
        username,
        "Username generated."
      );

      addActivity(
        "Username generated"
      );
    }
  );


/* =====================================================
   SAVE GENERATED PASSWORD
===================================================== */

$("saveGenerated")
  .addEventListener(
    "click",
    () => {

      if (!generatedPassword) {

        showToast(
          "Generate a password first."
        );

        return;
      }

      $("vaultPasswordInput").value =
        generatedPassword;

      const modal =
        bootstrap.Modal.getOrCreateInstance(
          $("credentialModal")
        );

      modal.show();
    }
  );


/* =====================================================
   MODAL PASSWORD GENERATOR
===================================================== */

$("generateModalPassword")
  .addEventListener(
    "click",
    () => {

      $("vaultPasswordInput").value =
        generatePassword(20);

      showToast(
        "Secure password generated."
      );
    }
  );


/* =====================================================
   ADD CREDENTIAL
===================================================== */

$("credentialForm")
  .addEventListener(
    "submit",
    event => {

      event.preventDefault();

      const site =
        $("siteInput").value.trim();

      const username =
        $("usernameInput").value.trim();

      const password =
        $("vaultPasswordInput").value;

      if (!site || !password) {

        showToast(
          "Website and password are required."
        );

        return;
      }


      const credential = {

        id:
          crypto.randomUUID(),

        site,

        username,

        password,

        category:
          $("categoryInput").value,

        expiry:
          $("expiryInput").value,

        notes:
          $("notesInput").value.trim(),

        favorite:
          $("favoriteInput").checked,

        createdAt:
          Date.now()

      };


      credentials.unshift(
        credential
      );

      saveJSON(
        STORAGE.credentials,
        credentials
      );


      renderVault();

      updateDashboard();

      addActivity(
        `Credential added: ${site}`
      );

      showToast(
        `${site} added to vault.`
      );


      $("credentialForm").reset();


      const modal =
        bootstrap.Modal.getInstance(
          $("credentialModal")
        );

      modal.hide();
    }
  );


/* =====================================================
   VAULT RENDER
===================================================== */

function renderVault() {

  const search =
    $("vaultSearch")
      .value
      .trim()
      .toLowerCase();

  const category =
    $("categoryFilter").value;


  const filtered =
    credentials.filter(item => {

      const matchesSearch =
        !search ||
        item.site.toLowerCase().includes(search) ||
        (item.username || "")
          .toLowerCase()
          .includes(search) ||
        (item.notes || "")
          .toLowerCase()
          .includes(search);


      const matchesCategory =
        category === "all" ||
        item.category === category;


      return (
        matchesSearch &&
        matchesCategory
      );
    });


  if (!filtered.length) {

    vaultGrid.innerHTML = `
      <div class="empty-vault">

        <div class="empty-icon">
          <i class="fa-solid fa-vault"></i>
        </div>

        <h3>
          ${
            credentials.length
              ? "No credentials found"
              : "Your vault is empty"
          }
        </h3>

        <p>
          ${
            credentials.length
              ? "Try changing your search or category filter."
              : "Add your first credential to start building your local password workspace."
          }
        </p>

        ${
          !credentials.length
            ? `
              <button
                class="btn-main"
                data-bs-toggle="modal"
                data-bs-target="#credentialModal"
              >
                Add First Credential
              </button>
            `
            : ""
        }

      </div>
    `;

    return;
  }


  vaultGrid.innerHTML =
    filtered
      .map(
        credentialCard
      )
      .join("");
}


/* =====================================================
   CREDENTIAL CARD
===================================================== */

function credentialCard(item) {

  const expiry =
    getExpiryStatus(
      item.expiry
    );

  const masked =
    "•".repeat(
      Math.min(
        item.password.length,
        16
      )
    );


  return `

    <article
      class="credential-card"
      data-id="${item.id}"
    >

      <div class="credential-top">

        <div class="site-info">

          <div class="site-icon">
            <i class="fa-solid fa-globe"></i>
          </div>

          <div>

            <strong>
              ${escapeHTML(item.site)}
            </strong>

            <span>
              ${escapeHTML(
                item.username || "No username"
              )}
            </span>

          </div>

        </div>


        <button
          class="favorite-button ${
            item.favorite
              ? "active"
              : ""
          }"
          onclick="toggleFavorite('${item.id}')"
          title="Favorite"
        >
          <i class="${
            item.favorite
              ? "fa-solid"
              : "fa-regular"
          } fa-star"></i>
        </button>

      </div>


      <div class="credential-meta">

        <span>
          <i class="fa-solid fa-layer-group"></i>
          ${escapeHTML(
            capitalize(item.category)
          )}
        </span>

        <span class="${
          expiry.className
        }">

          <i class="fa-solid fa-clock"></i>

          ${expiry.text}

        </span>

      </div>


      <div class="credential-password">

        <span id="pass-${item.id}">
          ${masked}
        </span>

        <button
          class="card-action"
          onclick="copyCredential('${item.id}')"
        >
          <i class="fa-regular fa-copy"></i>
        </button>

      </div>


      <div class="card-actions">

        <button
          class="card-action"
          onclick="revealCredential('${item.id}')"
        >
          <i class="fa-solid fa-eye"></i>
          View
        </button>

        <button
          class="card-action"
          onclick="copyCredential('${item.id}')"
        >
          <i class="fa-solid fa-copy"></i>
          Copy
        </button>

        <button
          class="card-action"
          onclick="deleteCredential('${item.id}')"
        >
          <i class="fa-solid fa-trash"></i>
          Delete
        </button>

      </div>

    </article>
  `;
}


/* =====================================================
   FAVORITE
===================================================== */

function toggleFavorite(id) {

  const item =
    credentials.find(
      credential =>
        credential.id === id
    );

  if (!item) {
    return;
  }

  item.favorite =
    !item.favorite;

  saveJSON(
    STORAGE.credentials,
    credentials
  );

  renderVault();

  addActivity(
    `${item.favorite ? "Added to" : "Removed from"} favorites: ${item.site}`
  );
}


/* =====================================================
   REVEAL
===================================================== */

function revealCredential(id) {

  const item =
    credentials.find(
      credential =>
        credential.id === id
    );

  if (!item) {
    return;
  }

  const element =
    document.getElementById(
      `pass-${id}`
    );

  if (!element) {
    return;
  }

  const isHidden =
    element.dataset.visible !== "true";

  element.dataset.visible =
    isHidden
      ? "true"
      : "false";

  element.textContent =
    isHidden
      ? item.password
      : "•".repeat(
          Math.min(
            item.password.length,
            16
          )
        );
}


/* =====================================================
   COPY CREDENTIAL
===================================================== */

function copyCredential(id) {

  const item =
    credentials.find(
      credential =>
        credential.id === id
    );

  if (!item) {
    return;
  }

  copyText(
    item.password,
    `${item.site} password copied.`
  );
}


/* =====================================================
   DELETE
===================================================== */

function deleteCredential(id) {

  const item =
    credentials.find(
      credential =>
        credential.id === id
    );

  if (!item) {
    return;
  }

  const confirmed =
    confirm(
      `Delete ${item.site} from the vault?`
    );

  if (!confirmed) {
    return;
  }

  credentials =
    credentials.filter(
      credential =>
        credential.id !== id
    );

  saveJSON(
    STORAGE.credentials,
    credentials
  );

  renderVault();

  updateDashboard();

  addActivity(
    `Credential deleted: ${item.site}`
  );

  showToast(
    "Credential deleted."
  );
}


/* =====================================================
   EXPIRY
===================================================== */

function getExpiryStatus(date) {

  if (!date) {

    return {
      text: "No expiry",
      className: ""
    };
  }


  const expiry =
    new Date(date);

  const today =
    new Date();

  today.setHours(
    0,
    0,
    0,
    0
  );


  const diff =
    Math.ceil(
      (
        expiry - today
      ) /
      86400000
    );


  if (diff < 0) {

    return {
      text: "Expired",
      className: "expiry-danger"
    };
  }


  if (diff <= 7) {

    return {
      text: `${diff}d left`,
      className: "expiry-danger"
    };
  }


  if (diff <= 30) {

    return {
      text: `${diff}d left`,
      className: "expiry-warning"
    };
  }


  return {
    text: `${diff}d left`,
    className: ""
  };
}


/* =====================================================
   DASHBOARD
===================================================== */

function updateDashboard() {

  const total =
    credentials.length;


  const weak =
    credentials.filter(
      item =>
        getPasswordScore(
          item.password
        ) < 60
    ).length;


  const passwordMap = {};

  credentials.forEach(
    item => {

      passwordMap[
        item.password
      ] =
        (passwordMap[
          item.password
        ] || 0) + 1;

    }
  );


  const reused =
    credentials.filter(
      item =>
        passwordMap[
          item.password
        ] > 1
    ).length;


  const expiring =
    credentials.filter(
      item => {

        const status =
          getExpiryStatus(
            item.expiry
          );

        return (
          status.text === "Expired" ||
          status.text.includes("d left") &&
          parseInt(
            status.text
          ) <= 30
        );
      }
    ).length;


  const strong =
    Math.max(
      total - weak,
      0
    );


  $("totalCredentials")
    .textContent = total;

  $("weakPasswords")
    .textContent = weak;

  $("reusedPasswords")
    .textContent = reused;

  $("expiringPasswords")
    .textContent = expiring;


  $("strongCount")
    .textContent = strong;

  $("weakCount")
    .textContent = weak;

  $("reuseCount")
    .textContent = reused;

  $("expiryCount")
    .textContent = expiring;


  const score =
    calculateSecurityScore(
      total,
      weak,
      reused,
      expiring
    );


  $("securityScore")
    .textContent = score;

  $("heroScore")
    .textContent = score;


  updateSecurityRing(
    score
  );


  $("strongBar").style.width =
    percentage(strong, total);

  $("weakBar").style.width =
    percentage(weak, total);

  $("reuseBar").style.width =
    percentage(reused, total);

  $("expiryBar").style.width =
    percentage(expiring, total);


  updateSecurityText(
    score,
    total,
    weak,
    reused,
    expiring
  );
}


function percentage(value, total) {

  if (!total) {
    return "0%";
  }

  return `${Math.min(
    100,
    Math.round(
      (value / total) * 100
    )
  )}%`;
}


function calculateSecurityScore(
  total,
  weak,
  reused,
  expiring
) {

  if (!total) {
    return 100;
  }

  let score = 100;

  score -=
    (weak / total) * 35;

  score -=
    (reused / total) * 30;

  score -=
    (expiring / total) * 15;

  return Math.max(
    0,
    Math.round(score)
  );
}


/* =====================================================
   SECURITY RING
===================================================== */

function updateSecurityRing(score) {

  const circumference =
    578;

  const offset =
    circumference -
    (score / 100) *
    circumference;

  $("securityRing")
    .style.strokeDashoffset =
    offset;
}


function updateSecurityText(
  score,
  total,
  weak,
  reused,
  expiring
) {

  if (!total) {

    $("securityTitle")
      .textContent =
      "Security baseline";

    $("securityDescription")
      .textContent =
      "Add credentials to receive a personalized security assessment.";

    return;
  }


  if (
    weak ||
    reused ||
    expiring
  ) {

    $("securityTitle")
      .textContent =
      "Attention required";

    $("securityDescription")
      .textContent =
      `${weak} weak, ${reused} reused and ${expiring} expiring credential(s) detected.`;

    return;
  }


  $("securityTitle")
    .textContent =
    "Vault looks healthy";

  $("securityDescription")
    .textContent =
    "No immediate password health issues were detected.";
}


/* =====================================================
   SECURITY SCAN
===================================================== */

$("runSecurityScan")
  .addEventListener(
    "click",
    async () => {

      const button =
        $("runSecurityScan");

      button.disabled =
        true;

      button.innerHTML =
        `
          <i class="fa-solid fa-spinner fa-spin"></i>
          Scanning...
        `;


      await delay(1000);

      updateDashboard();


      button.disabled =
        false;

      button.innerHTML =
        `
          <i class="fa-solid fa-radar"></i>
          Run Security Scan
        `;


      addActivity(
        "Security scan completed"
      );

      showToast(
        "Security scan completed."
      );
    }
  );


/* =====================================================
   EXPORT
===================================================== */

$("exportVault")
  .addEventListener(
    "click",
    () => {

      if (!credentials.length) {

        showToast(
          "There are no credentials to export."
        );

        return;
      }


      const data = {

        exportedAt:
          new Date().toISOString(),

        application:
          "VaultGen",

        credentials

      };


      const blob =
        new Blob(
          [
            JSON.stringify(
              data,
              null,
              2
            )
          ],
          {
            type:
              "application/json"
          }
        );


      const url =
        URL.createObjectURL(blob);


      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        `vaultgen-backup-${Date.now()}.json`;

      link.click();


      URL.revokeObjectURL(url);


      addActivity(
        "Vault exported as JSON"
      );

      showToast(
        "Vault backup exported."
      );
    }
  );


/* =====================================================
   IMPORT
===================================================== */

$("importVault")
  .addEventListener(
    "change",
    event => {

      const file =
        event.target.files[0];

      if (!file) {
        return;
      }


      const reader =
        new FileReader();


      reader.onload =
        () => {

          try {

            const data =
              JSON.parse(
                reader.result
              );


            const imported =
              Array.isArray(data)
                ? data
                : data.credentials;


            if (!Array.isArray(imported)) {

              throw new Error(
                "Invalid vault format"
              );
            }


            const cleaned =
              imported
                .filter(
                  item =>
                    item.site &&
                    item.password
                )
                .map(
                  item => ({
                    id:
                      item.id ||
                      crypto.randomUUID(),

                    site:
                      item.site,

                    username:
                      item.username || "",

                    password:
                      item.password,

                    category:
                      item.category ||
                      "other",

                    notes:
                      item.notes || "",

                    favorite:
                      Boolean(
                        item.favorite
                      ),

                    createdAt:
                      item.createdAt ||
                      Date.now(),

                    expiry:
                      item.expiry || ""
                  })
                );


            credentials =
              cleaned.concat(
                credentials
              );


            /*
              Remove exact duplicate IDs.
            */

            const unique =
              new Map();

            credentials.forEach(
              item => {
                unique.set(
                  item.id,
                  item
                );
              }
            );


            credentials =
              Array.from(
                unique.values()
              );


            saveJSON(
              STORAGE.credentials,
              credentials
            );


            renderVault();

            updateDashboard();

            addActivity(
              `${cleaned.length} credential(s) imported`
            );

            showToast(
              `${cleaned.length} credential(s) imported.`
            );

          } catch (error) {

            showToast(
              "Invalid VaultGen JSON file."
            );
          }

        };


      reader.readAsText(file);

      event.target.value = "";
    }
  );


/* =====================================================
   ACTIVITY
===================================================== */

function addActivity(message) {

  activities.unshift({

    id:
      crypto.randomUUID(),

    message,

    time:
      Date.now()

  });


  activities =
    activities.slice(
      0,
      100
    );


  saveJSON(
    STORAGE.activity,
    activities
  );

  renderActivity();
}


function renderActivity() {

  const log =
    $("activityLog");


  const items =
    activities.length
      ? activities
      : [];


  log.innerHTML =
    `
      <div class="activity-item">

        <span class="activity-time">
          NOW
        </span>

        <i class="fa-solid fa-power-off"></i>

        <span>
          VaultGen initialized
        </span>

      </div>
    `;


  items.forEach(
    item => {

      const row =
        document.createElement(
          "div"
        );

      row.className =
        "activity-item";


      row.innerHTML =
        `
          <span class="activity-time">
            ${formatTime(item.time)}
          </span>

          <i class="fa-solid fa-terminal"></i>

          <span>
            ${escapeHTML(item.message)}
          </span>
        `;


      log.appendChild(row);
    }
  );
}


function formatTime(timestamp) {

  const date =
    new Date(timestamp);

  return date.toLocaleTimeString(
    [],
    {
      hour:
        "2-digit",

      minute:
        "2-digit"
    }
  );
}


$("clearActivity")
  .addEventListener(
    "click",
    () => {

      activities = [];

      saveJSON(
        STORAGE.activity,
        activities
      );

      renderActivity();

      showToast(
        "Activity log cleared."
      );
    }
  );


/* =====================================================
   SEARCH
===================================================== */

$("vaultSearch")
  .addEventListener(
    "input",
    renderVault
  );


$("categoryFilter")
  .addEventListener(
    "change",
    renderVault
  );


/* =====================================================
   LENGTH
===================================================== */

lengthSlider
  .addEventListener(
    "input",
    () => {

      lengthValue.textContent =
        lengthSlider.value;
    }
  );


/* =====================================================
   PASSWORD EVENTS
===================================================== */

$("generateButton")
  .addEventListener(
    "click",
    runGenerator
  );


$("copyPassword")
  .addEventListener(
    "click",
    () => {

      copyText(
        generatedPassword,
        "Password copied."
      );
    }
  );


$("togglePassword")
  .addEventListener(
    "click",
    () => {

      passwordVisible =
        !passwordVisible;

      $("togglePassword")
        .innerHTML =
        passwordVisible
          ? `<i class="fa-solid fa-eye-slash"></i>`
          : `<i class="fa-solid fa-eye"></i>`;

      updatePasswordUI();
    }
  );


/* =====================================================
   KEYBOARD SHORTCUTS
===================================================== */

document.addEventListener(
  "keydown",
  event => {

    /*
      G = Generate
    */

    if (
      event.key.toLowerCase() === "g" &&
      !isTypingTarget(event.target)
    ) {

      event.preventDefault();

      runGenerator();
    }


    /*
      Ctrl + K = Search vault
    */

    if (
      event.ctrlKey &&
      event.key.toLowerCase() === "k"
    ) {

      event.preventDefault();

      $("vaultSearch").focus();

      document
        .getElementById("vault")
        .scrollIntoView({
          behavior:
            "smooth"
        });
    }


    /*
      Escape = hide password
    */

    if (
      event.key === "Escape" &&
      passwordVisible
    ) {

      passwordVisible =
        false;

      updatePasswordUI();
    }

  }
);


function isTypingTarget(element) {

  return (
    element.tagName === "INPUT" ||
    element.tagName === "TEXTAREA" ||
    element.tagName === "SELECT"
  );
}


/* =====================================================
   TOAST
===================================================== */

function showToast(message) {

  const toast =
    document.createElement(
      "div"
    );

  toast.className =
    "vault-toast";

  toast.innerHTML =
    `
      <i class="fa-solid fa-shield-halved"></i>

      <span>
        ${escapeHTML(message)}
      </span>
    `;


  toastContainer.appendChild(
    toast
  );


  setTimeout(
    () => {

      toast.style.opacity =
        "0";

      toast.style.transform =
        "translateY(10px)";

      setTimeout(
        () => toast.remove(),
        250
      );

    },
    3000
  );
}


/* =====================================================
   UTILITIES
===================================================== */

function capitalize(value) {

  if (!value) {
    return "";
  }

  return value
    .charAt(0)
    .toUpperCase() +
    value.slice(1);
}


function escapeHTML(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function delay(ms) {

  return new Promise(
    resolve =>
      setTimeout(
        resolve,
        ms
      )
  );
}


/* =====================================================
   SCROLL REVEAL
===================================================== */

const observer =
  new IntersectionObserver(
    entries => {

      entries.forEach(
        entry => {

          if (
            entry.isIntersecting
          ) {

            entry.target
              .classList
              .add("visible");

            observer.unobserve(
              entry.target
            );
          }

        }
      );

    },
    {
      threshold:
        0.08
    }
  );


document
  .querySelectorAll(".reveal")
  .forEach(
    element =>
      observer.observe(element)
  );


/* =====================================================
   ACTIVE NAVIGATION
===================================================== */

const sections =
  document.querySelectorAll(
    "main section[id]"
  );

const navLinks =
  document.querySelectorAll(
    ".nav-link"
  );


const navObserver =
  new IntersectionObserver(
    entries => {

      entries.forEach(
        entry => {

          if (
            entry.isIntersecting
          ) {

            navLinks
              .forEach(
                link =>
                  link.classList.remove(
                    "active"
                  )
              );


            const active =
              document.querySelector(
                `.nav-link[href="#${entry.target.id}"]`
              );


            if (active) {
              active.classList.add(
                "active"
              );
            }

          }

        }
      );

    },
    {
      rootMargin:
        "-30% 0px -60% 0px"
    }
  );


sections.forEach(
  section =>
    navObserver.observe(section)
);


/* =====================================================
   INITIALIZE
===================================================== */

function initialize() {

  lengthValue.textContent =
    lengthSlider.value;

  renderVault();

  updateDashboard();

  renderActivity();

  /*
    Create initial password so
    the interface does not look empty.
  */

  generatedPassword =
    generatePassword();

  updatePasswordUI();

  /*
    Do not add initial generated
    password to history/activity.
  */
}


initialize();