import test from "node:test";
import assert from "node:assert/strict";
import { maakHersteltoken, hashHersteltoken, hersteltokenGeldig } from "./hersteltoken";
import { secretsMatch } from "./vergelijk";

test("maakHersteltoken: de opgeslagen hash is niet het token", () => {
  const h = maakHersteltoken();
  assert.notEqual(h.hash, h.token);
  assert.ok(h.token.length > 20);
  // Wie de database leest mag daarmee geen wachtwoord kunnen herstellen.
  assert.ok(!h.hash.includes(h.token));
});

test("maakHersteltoken: twee tokens zijn niet gelijk", () => {
  assert.notEqual(maakHersteltoken().token, maakHersteltoken().token);
});

test("hersteltokenGeldig: het juiste token binnen de tijd is geldig", () => {
  const h = maakHersteltoken({ geldigMinuten: 60 });
  assert.equal(hersteltokenGeldig(h.token, h.hash, h.verlooptOp), true);
});

test("hersteltokenGeldig: een verkeerd token is ongeldig", () => {
  const h = maakHersteltoken();
  assert.equal(hersteltokenGeldig("iets-anders", h.hash, h.verlooptOp), false);
});

test("hersteltokenGeldig: verlopen is ongeldig, ook met het juiste token", () => {
  const verleden = new Date(Date.parse("2020-01-01T00:00:00Z"));
  const h = maakHersteltoken({ geldigMinuten: 60, nu: () => verleden });
  assert.equal(hersteltokenGeldig(h.token, h.hash, h.verlooptOp), false);
});

test("hersteltokenGeldig: lege invoer is ongeldig en werpt niet", () => {
  const h = maakHersteltoken();
  assert.equal(hersteltokenGeldig("", h.hash, h.verlooptOp), false);
  assert.equal(hersteltokenGeldig(h.token, "", h.verlooptOp), false);
  assert.equal(hersteltokenGeldig(h.token, h.hash, "geen-datum"), false);
});

test("hashHersteltoken is deterministisch, zodat je erop kunt zoeken", () => {
  assert.equal(hashHersteltoken("abc"), hashHersteltoken("abc"));
  assert.notEqual(hashHersteltoken("abc"), hashHersteltoken("abd"));
});

test("secretsMatch: gelijk is waar, ongelijk en ongelijke lengte zijn onwaar", () => {
  assert.equal(secretsMatch("abc", "abc"), true);
  assert.equal(secretsMatch("abc", "abd"), false);
  assert.equal(secretsMatch("abc", "abcd"), false);
  assert.equal(secretsMatch("", "abc"), false);
  assert.equal(secretsMatch("abc", undefined), false);
  assert.equal(secretsMatch(42 as unknown, "abc"), false);
});
