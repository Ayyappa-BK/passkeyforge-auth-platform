import { test, expect } from "@playwright/test";
test("real browser WebAuthn, MFA, recovery, credential management and logout", async ({
  page,
  context,
}) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  let { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  await page.goto("/");
  await page.getByRole("button", { name: /New here/ }).click();
  await page.getByLabel("Account name").fill("browser_" + Date.now());
  await page.getByLabel("Passkey name").fill("Browser passkey");
  await page
    .getByRole("button", { name: "Create passkey", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: /Your passkeys/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Generate new codes" }).click();
  await expect(page.locator(".recovery-list code")).toHaveCount(10);
  const codes = await page.locator(".recovery-list code").allTextContents();
  expect(codes).toHaveLength(10);
  await page.getByRole("button", { name: "I have saved my codes" }).click();
  // A second enrollment needs a different authenticator: excludeCredentials correctly blocks duplicates.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  const roaming = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  authenticatorId = roaming.authenticatorId;
  await page.getByRole("button", { name: "Add passkey", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page
    .getByRole("button", { name: "Remove Browser passkey" })
    .first()
    .click();
  await page
    .getByRole("button", { name: "Remove passkey", exact: true })
    .click();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  // Copy the test virtual credential into a second isolated browser context to verify JDBC session revocation.
  const { credentials: virtualCredentials } = await cdp.send(
    "WebAuthn.getCredentials",
    { authenticatorId },
  );
  const otherContext = await context.browser()!.newContext();
  const other = await otherContext.newPage();
  const otherCdp = await otherContext.newCDPSession(other);
  await otherCdp.send("WebAuthn.enable");
  const { authenticatorId: otherId } = await otherCdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    },
  );
  for (const credential of virtualCredentials)
    await otherCdp.send("WebAuthn.addCredential", {
      authenticatorId: otherId,
      credential,
    });
  await other.goto(new URL("/", page.url()).href);
  await other.getByRole("button", { name: "Continue with a passkey" }).click();
  await expect(
    other.getByRole("heading", { name: /Your passkeys/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Revoke other sessions" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Other sessions have been revoked",
  );
  await expect
    .poll(async () =>
      (
        await otherContext.request.get(new URL("/api/me", page.url()).href)
      ).status(),
    )
    .toBe(401);
  const synced = await otherCdp.send("WebAuthn.getCredentials", {
    authenticatorId: otherId,
  });
  for (const credential of synced.credentials) {
    await cdp.send("WebAuthn.removeCredential", {
      authenticatorId,
      credentialId: credential.credentialId,
    });
    await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
  }
  await otherContext.close();
  await page.getByRole("button", { name: "Set up authenticator" }).click();
  await expect(
    page.getByRole("dialog", { name: "Enroll authenticator" }),
  ).toBeVisible();
  await page.getByText("Enter a setup key manually").click();
  const secret = await page.locator("details code").textContent();
  expect(secret).toBeTruthy();
  // Uses Node's standard HMAC primitive only in this test, independently of backend's TOTP library.
  const { createHmac } = await import("node:crypto");
  const totp = (offset = 0) => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const c of secret!)
      bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
    const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
    const time = Buffer.alloc(8);
    time.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
    const mac = createHmac("sha1", key).update(time).digest();
    const start = mac[mac.length - 1] & 15;
    return ((mac.readUInt32BE(start) & 0x7fffffff) % 1000000)
      .toString()
      .padStart(6, "0");
  };
  await page.getByLabel("Verification code", { exact: true }).fill(totp());
  await page.getByRole("button", { name: "Verify authenticator" }).click();
  await expect(
    page.getByRole("dialog", { name: "Save recovery codes" }),
  ).toBeVisible();
  await expect(page.locator(".recovery-list code")).toHaveCount(10);
  const mfaCodes = await page.locator(".recovery-list code").allTextContents();
  await page.getByRole("button", { name: "I have saved my codes" }).click();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("button", { name: "Continue with a passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Verify your second factor" }),
  ).toBeVisible();
  await page.getByLabel("6-digit authenticator code").fill("000000");
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByLabel("6-digit authenticator code").fill(totp(1));
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(
    page.getByRole("heading", { name: /Your passkeys/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("button", { name: "Continue with a passkey" }).click();
  await page.getByRole("button", { name: "Use a recovery code" }).click();
  await page.getByLabel("Recovery code", { exact: true }).fill(mfaCodes[0]);
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(
    page.getByRole("heading", { name: /Your passkeys/ }),
  ).toBeVisible();
  const metrics = await page.request.get(
    "http://localhost:9090/actuator/prometheus",
  );
  expect(metrics.ok()).toBeTruthy();
  expect(await metrics.text()).toContain("forge_auth_events_total");
  await page.screenshot({
    path: "test-results/security-dashboard.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in securely" }),
  ).toBeVisible();
});
