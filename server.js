import express from "express";
import crypto from "node:crypto";

const {
  PAYPAL_CLIENT_ID, PAYPAL_SECRET, PAYPAL_WEBHOOK_ID,
  SHOPIFY_STORE, SHOPIFY_TOKEN, SHOPIFY_WEBHOOK_SECRET,
  PUBLIC_URL,
} = process.env;
const PP = process.env.PAYPAL_API || "https://api-m.sandbox.paypal.com";
const SHOP_API = `https://${SHOPIFY_STORE}/admin/api/2025-01/graphql.json`;

const seen = new Set();
const app = express();

async function ppToken() {
  const r = await fetch(`${PP}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: "Basic " + Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  return (await r.json()).access_token;
}

async function createPayPalOrder(shopifyOrderId, amount, currency) {
  const r = await fetch(`${PP}/v2/checkout/orders`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await ppToken()}`,
      "Content-Type": "application/json",
      "PayPal-Request-Id": `shopify-${shopifyOrderId}`,
    },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [{
        custom_id: String(shopifyOrderId),
        amount: { currency_code: currency, value: amount },
      }],
      payment_source: {
        paypal: {
          experience_context: {
            return_url: `${PUBLIC_URL}/paypal/return`,
            cancel_url: `${PUBLIC_URL}/paypal/cancel`,
            user_action: "PAY_NOW",
          },
        },
      },
    }),
  });
  const data = await r.json();
  const link = data.links?.find((l) => l.rel === "payer-action" || l.rel === "approve");
  return link?.href;
}

async function verifyPayPal(req, body) {
  const h = req.headers;
  const r = await fetch(`${PP}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await ppToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      auth_algo: h["paypal-auth-algo"],
      cert_url: h["paypal-cert-url"],
      transmission_id: h["paypal-transmission-id"],
      transmission_sig: h["paypal-transmission-sig"],
      transmission_time: h["paypal-transmission-time"],
      webhook_id: PAYPAL_WEBHOOK_ID,
      webhook_event: JSON.parse(body),
    }),
  });
  return (await r.json()).verification_status === "SUCCESS";
}

async function shopify(query, variables) {
  const r = await fetch(SHOP_API, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": SHOPIFY_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return r.json();
}

const markPaid = (id) =>
  shopify(
    `mutation($id: ID!) { orderMarkAsPaid(input:{id:$id}) { userErrors { message } } }`,
    { id: `gid://shopify/Order/${id}` },
  );

const setNote = (id, note) =>
  shopify(
    `mutation($input: OrderInput!) { orderUpdate(input:$input) { userErrors { message } } }`,
    { input: { id: `gid://shopify/Order/${id}`, note } },
  );

function verifyShopify(req, body) {
  const hmac = crypto.createHmac("sha256", SHOPIFY_WEBHOOK_SECRET).update(body).digest("base64");
  const got = req.headers["x-shopify-hmac-sha256"] || "";
  return got.length === hmac.length && crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(got));
}

app.post("/webhooks/shopify/orders-create", express.raw({ type: "*/*" }), async (req, res) => {
  const body = req.body.toString("utf8");
  if (!verifyShopify(req, body)) return res.sendStatus(401);
  res.sendStatus(200);

  const order = JSON.parse(body);
  const gateways = (order.payment_gateway_names || []).join(" ").toLowerCase();
  if (!gateways.includes("paypal") || order.financial_status === "paid") return;
  if (seen.has(`o-${order.id}`)) return;
  seen.add(`o-${order.id}`);

  const link = await createPayPalOrder(order.id, order.total_price, order.currency);
  if (!link) return console.error("Création ordre PayPal échouée", order.id);

  await setNote(order.id, `Lien de paiement PayPal : ${link}`);
  console.log(`Commande ${order.name} : ${link}`);
});

app.get("/paypal/return", async (req, res) => {
  const orderId = req.query.token;
  if (!orderId) return res.status(400).send("Paramètre manquant");
  await fetch(`${PP}/v2/checkout/orders/${orderId}/capture`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await ppToken()}`, "Content-Type": "application/json" },
  });
  res.send("Merci ! Votre paiement est en cours de confirmation.");
});

app.get("/paypal/cancel", (_req, res) => res.send("Paiement annulé."));

app.post("/webhooks/paypal", express.raw({ type: "*/*" }), async (req, res) => {
  const body = req.body.toString("utf8");
  if (!(await verifyPayPal(req, body))) return res.sendStatus(401);
  res.sendStatus(200);

  const evt = JSON.parse(body);
  if (evt.event_type !== "PAYMENT.CAPTURE.COMPLETED" || seen.has(evt.id)) return;
  seen.add(evt.id);

  const result = await markPaid(evt.resource.custom_id);
  console.log("Commande marquée payée :", evt.resource.custom_id, JSON.stringify(result));
});

app.get("/", (_req, res) => res.send("OK"));
app.listen(process.env.PORT || 3000, () => console.log("Serveur démarré"));