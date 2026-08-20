export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/auth/request-code" && request.method === "POST") {
      return handleRequestCode(env);
    }

    if (url.pathname === "/api/auth/verify-code" && request.method === "POST") {
      return handleVerifyCode(request, env);
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      return handlePasswordLogin(request, env);
    }

    // Owner-only: manage which email/password accounts can log into the admin panel.
    if (url.pathname === "/api/auth/admins" && request.method === "GET") {
      return handleListAdmins(request, env);
    }
    if (url.pathname === "/api/auth/register-admin" && request.method === "POST") {
      return handleRegisterAdmin(request, env);
    }
    if (url.pathname === "/api/auth/update-admin" && request.method === "POST") {
      return handleUpdateAdmin(request, env);
    }
    if (url.pathname === "/api/auth/remove-admin" && request.method === "POST") {
      return handleRemoveAdmin(request, env);
    }

    // Any logged-in admin can change their own password.
    if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
      return handleChangePassword(request, env);
    }

    // Owner-only: permanently wipe all order data (orders, indexes, quota usage).
    if (url.pathname === "/api/admin/reset-orders" && request.method === "POST") {
      return handleResetOrders(request, env);
    }

    // Public: menu + payment/delivery settings for the customer-facing page.
    if (url.pathname === "/api/menu" && request.method === "GET") {
      const itemsRaw = await env.WO_KV.get("wo:items");
      const settingsRaw = await env.WO_KV.get("wo:settings");
      return jsonResponse({
        items: itemsRaw ? JSON.parse(itemsRaw) : [],
        settings: settingsRaw ? JSON.parse(settingsRaw) : {}
      });
    }

    // Admin-only: fetch every order for one outlet in a single round-trip,
    // with the KV reads parallelized server-side. Optionally scoped to a
    // date range (from/to, matching the admin's date filter) — since order
    // IDs encode their creation date (WO-<CODE>-YYMMDD-####), out-of-range
    // orders are skipped before ever touching KV, not just filtered out of
    // the response after fetching everything.
    if (url.pathname === "/api/orders-bulk" && request.method === "GET") {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);
      const outletId = url.searchParams.get("outlet");
      if (!outletId) return jsonResponse({ error: "Missing outlet" }, 400);
      const perms = await getSessionPermissions(request, env);
      if (perms && !perms.owner && !perms.tabs.includes("orders")) {
        return jsonResponse({ error: "Akun ini tidak memiliki akses ke data pesanan." }, 403);
      }
      if (perms && !perms.owner && perms.outletAccess !== "all" && perms.outletAccess !== outletId) {
        return jsonResponse({ error: "Akun ini hanya bisa mengakses pesanan outlet yang diizinkan." }, 403);
      }
      const fromStr = url.searchParams.get("from") || "";
      const toStr = url.searchParams.get("to") || "";
      const idsRaw = await env.WO_KV.get("wo:order-ids:" + outletId);
      const allIds = idsRaw ? JSON.parse(idsRaw) : [];
      const ids = (fromStr || toStr)
        ? allIds.filter(id => {
            const d = parseOrderIdDate(id);
            if (!d) return true; // unparseable id — keep it, let the client-side date check catch it
            if (fromStr && d < fromStr) return false;
            if (toStr && d > toStr) return false;
            return true;
          })
        : allIds;
      const orders = await Promise.all(ids.map(async (id) => {
        try {
          const raw = await env.WO_KV.get("wo:order:" + id);
          return raw ? JSON.parse(raw) : null;
        } catch (e) {
          return null;
        }
      }));
      return jsonResponse({ orders: orders.filter(Boolean) });
    }

    // Admin-only: the actual used/quota numbers for a given outlet+date, both
    // halves at once. Deliberately separate from the public /api/quota below,
    // which only ever returns a boolean — these raw numbers are for the
    // admin's own Kuota view, not exposed to customers.
    if (url.pathname === "/api/admin/quota-detail" && request.method === "GET") {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);
      const outletId = url.searchParams.get("outlet");
      const date = url.searchParams.get("date");
      if (!outletId || !date) return jsonResponse({ error: "Parameter tidak lengkap" }, 400);
      const perms = await getSessionPermissions(request, env);
      if (perms && !perms.owner && !perms.tabs.includes("dashboard")) {
        return jsonResponse({ error: "Akun ini tidak memiliki akses ke Dashboard." }, 403);
      }
      if (perms && !perms.owner && perms.outletAccess !== "all" && perms.outletAccess !== outletId) {
        return jsonResponse({ error: "Akun ini hanya bisa mengakses kuota outlet yang diizinkan." }, 403);
      }
      const settingsRaw = await env.WO_KV.get("wo:settings");
      const settingsObj = settingsRaw ? JSON.parse(settingsRaw) : {};
      const outlet = (settingsObj.outlets || []).find(o => o.id === outletId);
      if (!outlet) return jsonResponse({ error: "Outlet tidak ditemukan" }, 400);
      const [usedAM, usedPM] = await Promise.all([
        getQuotaUsage(env, outletId, date, "am"),
        getQuotaUsage(env, outletId, date, "pm")
      ]);
      return jsonResponse({
        am: { used: usedAM, quota: getEffectiveQuota(outlet, "am") },
        pm: { used: usedPM, quota: getEffectiveQuota(outlet, "pm") }
      });
    }

    // Public: check whether a given outlet+date's pre-order quota is full.
    // Returns only a boolean, never the actual quota numbers.
    if (url.pathname === "/api/quota" && request.method === "GET") {
      return handleQuotaCheck(url, env);
    }

    // Public: create an order. All pricing, stock, quota, and fee logic is
    // computed and validated here server-side so a customer's browser can't
    // tamper with prices, stock counts, quotas, or delivery fees.
    if (url.pathname === "/api/orders" && request.method === "POST") {
      return handleCreateOrder(request, env);
    }

    // Public (token-gated): fetch an order's current status, used to let a
    // customer resume/check their order after closing or refreshing the tab.
    const orderGetMatch = url.pathname.match(/^\/api\/orders\/([^/]+)$/);
    if (orderGetMatch && request.method === "GET") {
      return handleGetOrder(url, env, decodeURIComponent(orderGetMatch[1]));
    }

    // Public (token-gated): submit payment proof for an order.
    const proofMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/proof$/);
    if (proofMatch && request.method === "POST") {
      return handleSubmitProof(request, env, decodeURIComponent(proofMatch[1]));
    }

    // Admin-only: create a Google Calendar event for a confirmed order.
    // Called by the client right after "Konfirmasi Pembayaran" — kept as a
    // separate best-effort call rather than baked into the status write, so a
    // calendar hiccup never blocks confirming an order.
    const calendarMatch = url.pathname.match(/^\/api\/orders\/([^/]+)\/calendar-event$/);
    if (calendarMatch && request.method === "POST") {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);
      return handleCreateCalendarEvent(env, decodeURIComponent(calendarMatch[1]));
    }
    // Called by the client when an order's status changes to "Gagal" — removes
    // the event so a failed order doesn't sit on the calendar looking booked.
    if (calendarMatch && request.method === "DELETE") {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);
      return handleDeleteCalendarEvent(env, decodeURIComponent(calendarMatch[1]));
    }
    // Admin-only diagnostic — walks through the Calendar setup step by step
    // and returns exactly where it fails, instead of the silent best-effort
    // behavior used everywhere else (which is correct for real order flow,
    // but useless for debugging setup problems).
    if (url.pathname === "/api/test-calendar" && request.method === "GET") {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);
      return handleTestCalendar(env);
    }

    // Everything under /api/kv/* is the admin panel's data channel
    // (menu editing, settings editing, order status changes, order listing).
    // Requires a valid session token from the email verification-code login.
    if (url.pathname.startsWith("/api/kv/")) {
      const isAdmin = await requireAdmin(request, env);
      if (!isAdmin) {
        return jsonResponse({ error: "Unauthorized" }, 401);
      }

      const key = decodeURIComponent(url.pathname.slice("/api/kv/".length));
      if (!key) {
        return jsonResponse({ error: "Missing key" }, 400);
      }

      const perms = await getSessionPermissions(request, env);
      const isWrite = request.method === "PUT" || request.method === "POST" || request.method === "DELETE";
      if (isWrite && perms && !perms.owner) {
        const tabForKey = tabForKvKey(key);
        if (tabForKey && !perms.tabs.includes(tabForKey)) {
          return jsonResponse({ error: "Akun ini tidak memiliki akses ke data ini." }, 403);
        }
        if (tabForKey === "orders" && !perms.canEditOrder && !perms.canEditStatus) {
          return jsonResponse({ error: "Akun ini tidak memiliki izin mengubah pesanan." }, 403);
        }
        // Outlet-scoped admins can only write orders belonging to their own
        // outlet — order IDs and their KV keys don't encode the outlet
        // directly, so this checks the order's stored outlet field.
        if (tabForKey === "orders" && perms.outletAccess !== "all" && key.startsWith("wo:order:")) {
          const existing = await env.WO_KV.get(key);
          if (existing) {
            const order = JSON.parse(existing);
            if (order.outlet !== perms.outletAccess) {
              return jsonResponse({ error: "Akun ini hanya bisa mengakses pesanan outlet yang diizinkan." }, 403);
            }
          }
        }
        if (tabForKey === "orders" && perms.outletAccess !== "all" && key.startsWith("wo:order-ids:")) {
          const outletIdInKey = key.slice("wo:order-ids:".length);
          if (outletIdInKey !== perms.outletAccess) {
            return jsonResponse({ error: "Akun ini hanya bisa mengakses pesanan outlet yang diizinkan." }, 403);
          }
        }
      }

      if (request.method === "GET") {
        const value = await env.WO_KV.get(key);
        if (value === null) {
          return jsonResponse({ error: "Not found" }, 404);
        }
        return new Response(value, { headers: { "Content-Type": "application/json" } });
      }

      if (request.method === "PUT" || request.method === "POST") {
        const body = await request.text();
        await env.WO_KV.put(key, body);
        return jsonResponse({ ok: true });
      }

      if (request.method === "DELETE") {
        await env.WO_KV.delete(key);
        return jsonResponse({ ok: true });
      }

      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    return env.ASSETS.fetch(request);
  },

  // Runs on the schedule set in wrangler.toml ([triggers] crons).
  // Marks unpaid orders as "failed" once their payment deadline has passed,
  // releasing any pre-order quota they were holding, so orders expire even
  // if nobody has the site open at that moment.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(expireOverdueOrders(env));
  }
};

// Order IDs look like WO-<OUTLET_CODE>-YYMMDD-####, with YYMMDD set from
// the creation timestamp — this recovers that date as YYYY-MM-DD for
// comparison against the admin's date-range filter.
function parseOrderIdDate(id) {
  const parts = String(id).split("-");
  if (parts.length < 3) return null;
  const raw = parts[2];
  if (!/^\d{6}$/.test(raw)) return null;
  return `20${raw.slice(0, 2)}-${raw.slice(2, 4)}-${raw.slice(4, 6)}`;
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function getSessionEmail(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;
  return await env.WO_KV.get("auth:session:" + token);
}

async function requireAdmin(request, env) {
  const email = await getSessionEmail(request, env);
  return !!email;
}

async function getSessionPermissions(request, env) {
  const email = await getSessionEmail(request, env);
  if (!email) return null;
  if (isOwnerEmail(email, env)) return { owner: true };
  const adminsRaw = await env.WO_KV.get("wo:admins");
  const admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  const account = admins.find(a => a.email.toLowerCase() === email.toLowerCase());
  // No stored account (shouldn't normally happen for a valid session) or an
  // account predating granular permissions both default to full access, so
  // nobody's access silently narrows on upgrade.
  if (!account) return { owner: false, outletAccess: "all", tabs: VALID_TABS.slice(), canEditOrder: true, canEditStatus: true };
  const normalized = normalizeAdminForResponse(account);
  return { owner: false, ...normalized };
}

function isOwnerEmail(email, env) {
  return !!email && email.toLowerCase() === String(env.ADMIN_EMAIL || "").toLowerCase();
}

// Maps a raw KV key to the admin tab that governs write access to it. Keys
// not covered here (public/shared data like wo:items sub-parts) fall
// through with no tab restriction beyond requiring a valid session.
function tabForKvKey(key) {
  if (key.startsWith("wo:order:") || key.startsWith("wo:order-ids:") || key.startsWith("wo:preorder-usage:")) return "orders";
  if (key === "wo:items") return "items";
  if (key === "wo:settings") return "outlet"; // shared across Outlet/Pesan/Lainnya -- see note in handleUpdateAdmin
  if (key === "wo:admins") return null; // admin management has its own owner-only check, not tab-gated
  return null;
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function todayStr(now) {
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
}

// Mirrors the client-side lead-time logic: if it's past the outlet's cutoff
// hour, "today" for lead-time purposes rolls over to tomorrow before adding
// leadDays. E.g. leadDays=1, cutoffHour=14: ordering before 2pm -> tomorrow
// is the earliest date; ordering after 2pm -> the day after tomorrow.
function minOrderDateServer(outlet, now) {
  const cutoff = outlet.cutoffHour != null ? Number(outlet.cutoffHour) : 14;
  const lead = outlet.leadDays != null ? Number(outlet.leadDays) : 1;
  const base = new Date(now);
  base.setHours(0, 0, 0, 0);
  if (now.getHours() >= cutoff) base.setDate(base.getDate() + 1);
  base.setDate(base.getDate() + lead);
  return base;
}

function formatDateDMYServer(str) {
  if (!str) return str;
  const parts = String(str).split("-");
  if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
  return str;
}

function dateStrToDate(str) {
  const [y, m, d] = str.split("-").map(Number);
  return new Date(y, (m || 1) - 1, d || 1);
}

function computeDeliveryFeeServer(postalCode, outlet, totalQty) {
  if (!outlet) return { fee: null, label: "outlet tidak valid" };
  if (!postalCode) return { fee: null, label: "kode pos tidak valid" };
  const code = String(postalCode).trim();

  // New system: postal code -> distance band (from uploaded map) -> fee (motor/mobil by cart size)
  if (outlet.postalDistanceMap && Object.keys(outlet.postalDistanceMap).length > 0) {
    const band = outlet.postalDistanceMap[code];
    if (!band) return { fee: null, label: "di luar area pengiriman" };
    const tiers = Array.isArray(outlet.distanceFeeTiers) ? outlet.distanceFeeTiers : [];
    const tier = tiers.find(t => t.band === band);
    if (!tier) return { fee: null, label: "tingkat jarak belum diatur" };
    const threshold = outlet.vehicleThresholdCups != null ? Number(outlet.vehicleThresholdCups) : 20;
    const useMobil = Number(totalQty || 0) >= threshold;
    return { fee: useMobil ? (Number(tier.mobilFee) || 0) : (Number(tier.motorFee) || 0), label: band };
  }

  // Legacy: numeric postal-code-difference tiers
  const base = Number(outlet.postalCode) || 0;
  const target = Number(code);
  if (isNaN(target)) return { fee: null, label: "kode pos tidak valid" };
  const diff = Math.abs(target - base);
  const tiers = Array.isArray(outlet.tiers)
    ? [...outlet.tiers].sort((a, b) => Number(a.maxDiff) - Number(b.maxDiff))
    : [];
  for (let i = 0; i < tiers.length; i++) {
    if (diff <= Number(tiers[i].maxDiff)) {
      return { fee: Number(tiers[i].fee) || 0, label: `zona ${i + 1}` };
    }
  }
  return { fee: null, label: "di luar area pengiriman" };
}

function computePackagingFeeServer(totalQty, outlet) {
  if (!outlet) return 0;
  if (Array.isArray(outlet.packagingTiers) && outlet.packagingTiers.length > 0) {
    const tiers = [...outlet.packagingTiers].sort((a, b) => Number(a.maxQty) - Number(b.maxQty));
    for (const t of tiers) {
      if (totalQty <= Number(t.maxQty)) return Number(t.fee) || 0;
    }
    return Number(tiers[tiers.length - 1].fee) || 0;
  }
  const freeUnder = outlet.packagingFreeUnder != null ? Number(outlet.packagingFreeUnder) : 12;
  const perUnit = outlet.packagingFeePerUnit != null ? Number(outlet.packagingFeePerUnit) : 30000;
  return freeUnder > 0 ? Math.floor(totalQty / freeUnder) * perUnit : 0;
}

function halfForTime(timeStr) {
  if (!timeStr) return "am";
  const hour = parseInt(String(timeStr).split(":")[0], 10);
  return (isNaN(hour) || hour < 12) ? "am" : "pm";
}

function quotaKey(outletId, dateStr, half) {
  return `wo:preorder-usage:${outletId}:${dateStr}:${half}`;
}

async function getQuotaUsage(env, outletId, dateStr, half) {
  const raw = await env.WO_KV.get(quotaKey(outletId, dateStr, half));
  return raw ? Number(raw) || 0 : 0;
}

// Outlets saved before the AM/PM quota split still have only the old single
// "preorderDailyQuota" field — until the admin re-saves the Outlet tab (which
// writes the new split fields), fall back to that old value for both halves
// rather than treating an unmigrated outlet as having zero quota / fully booked.
function getEffectiveQuota(outlet, half) {
  const newVal = half === "am" ? outlet.preorderDailyQuotaAM : outlet.preorderDailyQuotaPM;
  if (newVal != null) return Number(newVal) || 0;
  if (outlet.preorderDailyQuota != null) return Number(outlet.preorderDailyQuota) || 0;
  return 0;
}

async function handleQuotaCheck(url, env) {
  const outletId = url.searchParams.get("outlet");
  const date = url.searchParams.get("date");
  const qtyParam = url.searchParams.get("qty");
  const qty = qtyParam ? Number(qtyParam) || 0 : 1;
  if (!outletId || !date) return jsonResponse({ error: "Parameter tidak lengkap" }, 400);

  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settings = settingsRaw ? JSON.parse(settingsRaw) : {};
  const outlet = (settings.outlets || []).find(o => o.id === outletId);
  if (!outlet) return jsonResponse({ error: "Outlet tidak ditemukan" }, 400);

  const quotaAM = getEffectiveQuota(outlet, "am");
  const quotaPM = getEffectiveQuota(outlet, "pm");
  const usedAM = await getQuotaUsage(env, outletId, date, "am");
  const usedPM = await getQuotaUsage(env, outletId, date, "pm");
  const availableAM = (usedAM + qty) <= quotaAM;
  const availablePM = (usedPM + qty) <= quotaPM;

  const timeParam = url.searchParams.get("time");
  if (timeParam) {
    const half = halfForTime(timeParam);
    const available = half === "am" ? availableAM : availablePM;
    const otherHalf = half === "am" ? "pm" : "am";
    const otherHalfAvailable = half === "am" ? availablePM : availableAM;
    const otherHalfRemaining = Math.max(0, (half === "am" ? quotaPM - usedPM : quotaAM - usedAM));
    return jsonResponse({ available, half, otherHalf, otherHalfAvailable, otherHalfRemaining });
  }
  // No specific time given — return both halves so the client can annotate the time dropdown.
  return jsonResponse({ availableAM, availablePM });
}

async function handleCreateOrder(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return jsonResponse({ error: "Permintaan tidak valid" }, 400);
  if (!Array.isArray(body.items) || body.items.length === 0) {
    return jsonResponse({ error: "Keranjang masih kosong." }, 400);
  }
  if (!body.customerName || !body.whatsapp) {
    return jsonResponse({ error: "Nama dan nomor WhatsApp wajib diisi." }, 400);
  }
  if (!body.deliveryDate || !body.deliveryTime) {
    return jsonResponse({ error: "Tanggal dan jam pengiriman wajib diisi." }, 400);
  }
  if (!body.outlet) {
    return jsonResponse({ error: "Pilih outlet dulu." }, 400);
  }

  const itemsRaw = await env.WO_KV.get("wo:items");
  const settingsRaw = await env.WO_KV.get("wo:settings");
  const items = itemsRaw ? JSON.parse(itemsRaw) : [];
  const settings = settingsRaw ? JSON.parse(settingsRaw) : {};

  const outlet = (settings.outlets || []).find(o => o.id === body.outlet);
  if (!outlet) {
    return jsonResponse({ error: "Outlet tidak ditemukan." }, 400);
  }
  if (outlet.active === false) {
    return jsonResponse({ error: "Outlet ini sedang tidak aktif." }, 400);
  }

  if (Array.isArray(outlet.blockedDates) && outlet.blockedDates.includes(body.deliveryDate)) {
    return jsonResponse({ error: `Outlet ${outlet.name} tutup pada tanggal ini.` }, 400);
  }

  const now = new Date();
  const todayString = todayStr(now);
  const orderType = body.deliveryDate === todayString ? "today" : "preorder";

  if (orderType === "today" && outlet.allowSameDay === false) {
    return jsonResponse({ error: "Outlet ini hanya menerima pre-order, tidak bisa untuk hari ini." }, 400);
  }

  const minDate = minOrderDateServer(outlet, now);
  if (orderType !== "today" && dateStrToDate(body.deliveryDate) < minDate) {
    return jsonResponse({ error: "Tanggal pengiriman yang dipilih sudah tidak tersedia. Silakan pilih tanggal lain." }, 400);
  }

  const orderItems = [];
  let drinkQty = 0;
  for (const reqItem of body.items) {
    const it = items.find(i => i.id === reqItem.id);
    const qty = Number(reqItem.qty) || 0;
    if (!it) return jsonResponse({ error: "Menu tidak tersedia di outlet ini." }, 400);
    const outletData = it.outlets ? it.outlets[outlet.id] : null;
    if (!outletData || !outletData.active) {
      return jsonResponse({ error: `${it.name} tidak tersedia di outlet ini.` }, 400);
    }
    if (qty <= 0) return jsonResponse({ error: "Jumlah item tidak valid." }, 400);

    let sizeLabel = "", extraPrice = 0;
    const hasSizes = Array.isArray(it.sizes) && it.sizes.length > 0;
    if (hasSizes) {
      const size = it.sizes.find(s => s.id === reqItem.sizeId);
      if (!size) return jsonResponse({ error: `Pilih ukuran untuk ${it.name}.` }, 400);
      sizeLabel = size.label;
      extraPrice = Number(size.extraPrice) || 0;
      if (orderType === "today") {
        const stock = (outletData.sizeStock && outletData.sizeStock[size.id]) || 0;
        if (qty > stock) return jsonResponse({ error: `Stok ${it.name} (${size.label}) di ${outlet.name} tidak mencukupi lagi.` }, 400);
      }
    } else if (orderType === "today") {
      const stock = Number(outletData.stock) || 0;
      if (qty > stock) return jsonResponse({ error: `Stok ${it.name} di ${outlet.name} tidak mencukupi lagi.` }, 400);
    }

    const category = it.category || "drink";
    if (category !== "addon") drinkQty += qty;
    const note = it.notesEnabled ? String(reqItem.note || "").trim().slice(0, 200) : "";

    orderItems.push({
      id: it.id,
      name: it.name,
      sizeId: hasSizes ? reqItem.sizeId : null,
      sizeLabel,
      price: it.price + extraPrice,
      qty,
      category,
      note
    });
  }

  const totalQty = body.items.reduce((s, i) => s + (Number(i.qty) || 0), 0);

  if (orderType === "preorder") {
    const minCups = Number(outlet.preorderMinCups) != null ? Number(outlet.preorderMinCups) : 6;
    if (drinkQty < minCups) {
      return jsonResponse({ error: `Minimal pre-order adalah ${minCups} cup.` }, 400);
    }
    const half = halfForTime(body.deliveryTime);
    const quota = getEffectiveQuota(outlet, half);
    const used = await getQuotaUsage(env, outlet.id, body.deliveryDate, half);
    if (used + totalQty > quota) {
      return jsonResponse({ error: "Kuota pre-order untuk jadwal ini sudah penuh.", quotaFull: true }, 409);
    }
  }

  const fulfillment = body.fulfillment === "delivery" ? "delivery" : "pickup";
  if (fulfillment === "delivery" && outlet.deliveryEnabled === false) {
    return jsonResponse({ error: "Outlet ini tidak menerima pengiriman — hanya ambil sendiri." }, 400);
  }
  let deliveryFee = 0, deliveryFeeLabel = "", address = "", postalCode = "";
  let ordererAddress = "", ordererPostalCode = "", sameAsRecipient = true;
  let recipientName = "", recipientWhatsapp = "", recipientAddress = "", recipientPostalCode = "";
  if (fulfillment === "delivery") {
    ordererAddress = String(body.ordererAddress || "").slice(0, 500);
    ordererPostalCode = String(body.ordererPostalCode || "").slice(0, 10);
    sameAsRecipient = body.sameAsRecipient !== false;
    if (!ordererAddress || !ordererPostalCode) {
      return jsonResponse({ error: "Alamat dan kode pos wajib diisi untuk pengiriman." }, 400);
    }
    if (!sameAsRecipient) {
      recipientName = String(body.recipientName || "").slice(0, 200);
      recipientWhatsapp = String(body.recipientWhatsapp || "").slice(0, 40);
      recipientAddress = String(body.recipientAddress || "").slice(0, 500);
      recipientPostalCode = String(body.recipientPostalCode || "").slice(0, 10);
      if (!recipientName || !recipientWhatsapp || !recipientAddress || !recipientPostalCode) {
        return jsonResponse({ error: "Data penerima wajib diisi lengkap." }, 400);
      }
    }
    address = sameAsRecipient ? ordererAddress : recipientAddress;
    postalCode = sameAsRecipient ? ordererPostalCode : recipientPostalCode;
    const result = computeDeliveryFeeServer(postalCode, outlet, drinkQty);
    if (result.fee === null) {
      return jsonResponse({ error: "Kode pos ini di luar area pengiriman outlet yang dipilih." }, 400);
    }
    deliveryFee = result.fee;
    deliveryFeeLabel = result.label;
  }

  const subtotal = orderItems.reduce((s, i) => s + i.price * i.qty, 0);
  const packagingFee = computePackagingFeeServer(drinkQty, outlet);
  const total = subtotal + deliveryFee + packagingFee;

  // Today's orders draw down real stock. Pre-orders draw down the daily
  // quota instead, checked/reserved just before writing the order.
  if (orderType === "today") {
    for (const oi of orderItems) {
      const it = items.find(i => i.id === oi.id);
      const outletData = it.outlets[outlet.id];
      if (oi.sizeId) {
        outletData.sizeStock[oi.sizeId] = Math.max(0, (outletData.sizeStock[oi.sizeId] || 0) - oi.qty);
      } else {
        outletData.stock = Math.max(0, (outletData.stock || 0) - oi.qty);
      }
    }
    await env.WO_KV.put("wo:items", JSON.stringify(items));
  } else {
    const half = halfForTime(body.deliveryTime);
    const used = await getQuotaUsage(env, outlet.id, body.deliveryDate, half);
    await env.WO_KV.put(quotaKey(outlet.id, body.deliveryDate, half), String(used + totalQty));
  }

  const orderIdsKey = "wo:order-ids:" + outlet.id;
  const idxRaw = await env.WO_KV.get(orderIdsKey);
  const idx = idxRaw ? JSON.parse(idxRaw) : [];
  const seq = idx.length + 1;
  const dateStr = now.toISOString().slice(2, 10).replace(/-/g, "");
  const outletCode = (outlet.code || outlet.id.slice(0, 3)).toUpperCase();
  const orderId = `WO-${outletCode}-${dateStr}-${String(seq).padStart(4, "0")}`;
  const timeoutMin = Number(settings.unpaidTimeoutMinutes) || 60;
  const paymentDeadline = new Date(now.getTime() + timeoutMin * 60000).toISOString();
  const accessToken = crypto.randomUUID();

  const order = {
    id: orderId,
    outlet: outlet.id,
    outletName: outlet.name,
    outletAddress: outlet.address || "",
    outletBankName: outlet.bankName || "",
    outletBankAccount: outlet.bankAccount || "",
    outletBankHolder: outlet.bankHolder || "",
    orderType,
    createdAt: now.toISOString(),
    customerName: String(body.customerName).slice(0, 200),
    whatsapp: String(body.whatsapp).slice(0, 40),
    deliveryDate: String(body.deliveryDate).slice(0, 20),
    deliveryTime: String(body.deliveryTime).slice(0, 20),
    fulfillment,
    address,
    postalCode,
    ordererAddress,
    ordererPostalCode,
    sameAsRecipient,
    recipientName,
    recipientWhatsapp,
    recipientAddress,
    recipientPostalCode,
    deliveryFee,
    deliveryFeeLabel,
    packagingFee,
    note: String(body.note || "").slice(0, 500),
    items: orderItems,
    total,
    proofImage: null,
    status: "unpaid",
    paymentDeadline,
    accessToken
  };

  await env.WO_KV.put("wo:order:" + orderId, JSON.stringify(order));
  idx.push(orderId);
  await env.WO_KV.put(orderIdsKey, JSON.stringify(idx));

  return jsonResponse({ ok: true, order });
}

async function handleGetOrder(url, env, orderId) {
  const token = url.searchParams.get("token") || "";
  const raw = await env.WO_KV.get("wo:order:" + orderId);
  if (!raw) return jsonResponse({ error: "Pesanan tidak ditemukan." }, 404);
  const order = JSON.parse(raw);
  if (!order.accessToken || order.accessToken !== token) {
    return jsonResponse({ error: "Tidak diizinkan." }, 403);
  }
  return jsonResponse({ ok: true, order });
}

async function sendTelegramNotification(env, chatId, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text })
    });
  } catch (e) {
    // Best-effort only — a notification failure should never break the actual order flow.
  }
}

// --- Google Calendar integration -------------------------------------------
// Auth is via a Service Account: a self-signed JWT is exchanged for a short-
// lived access token (standard Google server-to-server OAuth flow), rather
// than an interactive user login — appropriate since this runs unattended
// whenever an order is confirmed, with nobody present to click through a
// consent screen.

function base64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlFromBytes(buf) {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function handleTestCalendar(env) {
  if (!env.GOOGLE_SERVICE_ACCOUNT_KEY) {
    return jsonResponse({ error: "GOOGLE_SERVICE_ACCOUNT_KEY belum diatur sebagai secret di Cloudflare." }, 400);
  }
  let keyData;
  try {
    keyData = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_KEY);
  } catch (e) {
    return jsonResponse({ error: "GOOGLE_SERVICE_ACCOUNT_KEY bukan JSON yang valid — pastikan seluruh isi file .json ter-paste, termasuk { di awal dan } di akhir. Detail: " + e.message }, 400);
  }
  if (!keyData.client_email || !keyData.private_key) {
    return jsonResponse({ error: "JSON yang tersimpan tidak punya field client_email atau private_key — kemungkinan file yang di-paste salah atau terpotong." }, 400);
  }

  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settingsObj = settingsRaw ? JSON.parse(settingsRaw) : {};
  const calendarId = settingsObj.googleCalendarId;
  if (!calendarId) {
    return jsonResponse({ error: "ID Google Calendar belum diisi di tab Lainnya." }, 400);
  }

  let accessToken;
  try {
    accessToken = await getGoogleAccessToken(env);
  } catch (e) {
    return jsonResponse({ error: "Gagal membuat token akses (kemungkinan private_key salah format): " + e.message }, 500);
  }
  if (!accessToken) {
    return jsonResponse({ error: "Google menolak permintaan token — client_email atau private_key kemungkinan salah, atau Calendar API belum di-enable di project Google Cloud-nya." }, 500);
  }

  try {
    const testRes = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}`, {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    const testData = await testRes.json();
    if (!testRes.ok) {
      const msg = testData.error ? testData.error.message : JSON.stringify(testData);
      return jsonResponse({ error: `Google Calendar menolak (${testRes.status}): ${msg}. Kemungkinan besar: kalender ini belum di-share ke ${keyData.client_email}, atau ID Calendar-nya salah.` }, 500);
    }
    return jsonResponse({ ok: true, message: `Berhasil terhubung ke kalender "${testData.summary}". Semua bagian (secret, ID, izin akses) sudah benar.` });
  } catch (e) {
    return jsonResponse({ error: "Gagal menghubungi Google Calendar API: " + e.message }, 500);
  }
}

async function getGoogleAccessToken(env) {
  const keyData = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_KEY);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: keyData.client_email,
    scope: "https://www.googleapis.com/auth/calendar",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(keyData.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );
  const jwt = `${signingInput}.${base64urlFromBytes(signature)}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${jwt}`
  });
  const data = await res.json();
  return data.access_token || null;
}

async function createGoogleCalendarEvent(env, order) {
  if (!env.GOOGLE_SERVICE_ACCOUNT_KEY) return null;
  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settingsObj = settingsRaw ? JSON.parse(settingsRaw) : {};
  const calendarId = settingsObj.googleCalendarId;
  if (!calendarId) return null;

  try {
    const accessToken = await getGoogleAccessToken(env);
    if (!accessToken) return null;

    const [startStr, endStrRaw] = String(order.deliveryTime || "00:00-01:00").split(/[–-]/).map(s => s.trim());
    const endStr = endStrRaw || startStr;
    const alamat = order.fulfillment === "delivery" ? (order.address || "-") : (order.outletAddress || "-");
    const itemsText = (order.items || [])
      .map(i => `${i.qty}x ${i.name}${i.sizeLabel ? " (" + i.sizeLabel + ")" : ""}${i.note ? ` — catatan: ${i.note}` : ""}`)
      .join("\n");

    const descriptionLines = [
      `Invoice: ${order.id}`,
      `Nama: ${order.customerName}`,
      `WhatsApp: ${order.whatsapp}`,
      `Outlet: ${order.outletName || order.outlet}`,
      `Metode: ${order.fulfillment === "delivery" ? "Diantar" : "Ambil sendiri"}`,
      `Alamat: ${alamat}`,
      "",
      "Item:",
      itemsText,
      "",
      `Total: Rp${Number(order.total || 0).toLocaleString("id-ID")}`
    ];
    if (order.note) descriptionLines.push(`Catatan: ${order.note}`);

    const event = {
      summary: `${order.id} — ${order.customerName} (${order.outletName || order.outlet})`,
      description: descriptionLines.join("\n"),
      start: { dateTime: `${order.deliveryDate}T${startStr}:00`, timeZone: "Asia/Jakarta" },
      end: { dateTime: `${order.deliveryDate}T${endStr}:00`, timeZone: "Asia/Jakarta" },
      reminders: {
        useDefault: false,
        overrides: [
          { method: "popup", minutes: 2880 },
          { method: "popup", minutes: 1440 },
          { method: "popup", minutes: 120 }
        ]
      }
    };

    const res = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(event)
    });
    const data = await res.json();
    return data.id || null;
  } catch (e) {
    // Best-effort only — a calendar failure should never block order confirmation.
    return null;
  }
}

async function deleteGoogleCalendarEvent(env, eventId) {
  if (!env.GOOGLE_SERVICE_ACCOUNT_KEY || !eventId) return;
  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settingsObj = settingsRaw ? JSON.parse(settingsRaw) : {};
  const calendarId = settingsObj.googleCalendarId;
  if (!calendarId) return;
  try {
    const accessToken = await getGoogleAccessToken(env);
    if (!accessToken) return;
    await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
  } catch (e) {
    // Best-effort only.
  }
}

async function handleCreateCalendarEvent(env, orderId) {
  const raw = await env.WO_KV.get("wo:order:" + orderId);
  if (!raw) return jsonResponse({ error: "Pesanan tidak ditemukan." }, 404);
  const order = JSON.parse(raw);
  // calendarEventId (rather than a one-way boolean) reflects whether a *live*
  // event currently exists — it gets cleared on deletion, so a later re-
  // confirmation after "Gagal" correctly creates a fresh event instead of
  // being silently skipped.
  if (order.calendarEventId) {
    return jsonResponse({ ok: true, skipped: true });
  }
  const eventId = await createGoogleCalendarEvent(env, order);
  if (eventId) {
    order.calendarEventId = eventId;
    await env.WO_KV.put("wo:order:" + orderId, JSON.stringify(order));
  }
  return jsonResponse({ ok: true });
}

async function handleDeleteCalendarEvent(env, orderId) {
  const raw = await env.WO_KV.get("wo:order:" + orderId);
  if (!raw) return jsonResponse({ error: "Pesanan tidak ditemukan." }, 404);
  const order = JSON.parse(raw);
  if (!order.calendarEventId) {
    return jsonResponse({ ok: true, skipped: true });
  }
  await deleteGoogleCalendarEvent(env, order.calendarEventId);
  delete order.calendarEventId;
  await env.WO_KV.put("wo:order:" + orderId, JSON.stringify(order));
  return jsonResponse({ ok: true });
}

async function handleSubmitProof(request, env, orderId) {
  const body = await request.json().catch(() => null);
  if (!body || !body.proofImage) {
    return jsonResponse({ error: "Bukti pembayaran tidak ditemukan." }, 400);
  }
  const raw = await env.WO_KV.get("wo:order:" + orderId);
  if (!raw) return jsonResponse({ error: "Pesanan tidak ditemukan." }, 404);
  const order = JSON.parse(raw);
  if (!order.accessToken || order.accessToken !== body.token) {
    return jsonResponse({ error: "Tidak diizinkan." }, 403);
  }
  if (order.status !== "unpaid") {
    return jsonResponse({ error: "Pesanan ini sudah tidak menunggu pembayaran." }, 400);
  }
  order.proofImages = Array.isArray(order.proofImages) ? order.proofImages : (order.proofImage ? [order.proofImage] : []);
  order.proofImages.push(body.proofImage);
  order.status = "awaiting";
  await env.WO_KV.put("wo:order:" + orderId, JSON.stringify(order));

  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settingsObj = settingsRaw ? JSON.parse(settingsRaw) : {};
  if (settingsObj.telegramChatId) {
    const itemsText = (order.items || [])
      .map(i => `• ${i.qty}x ${i.name}${i.sizeLabel ? " (" + i.sizeLabel + ")" : ""}${i.note ? ` — catatan: ${i.note}` : ""}`)
      .join("\n");
    const defaultTemplate = "🔔 Pesanan baru menunggu konfirmasi!\n\nInvoice: {invoice}\nOutlet: {outlet}\nNama: {nama}\nWhatsApp: {whatsapp}\nKirim: {tanggal}, {jam}\nTotal: {total}\n\n{items}";
    const template = (settingsObj.messageTemplates && settingsObj.messageTemplates.telegramNotify) || defaultTemplate;
    const vars = {
      invoice: order.id,
      outlet: order.outletName || order.outlet,
      nama: order.customerName,
      whatsapp: order.whatsapp,
      tanggal: formatDateDMYServer(order.deliveryDate),
      jam: order.deliveryTime || "-",
      total: "Rp" + Number(order.total || 0).toLocaleString("id-ID"),
      items: itemsText,
      metode: order.fulfillment === "delivery" ? "diantar" : "diambil",
      alamat: order.fulfillment === "delivery" ? (order.address || "-") : (order.outletAddress || "-")
    };
    const text = template.replace(/\{(\w+)\}/g, (m, k) => (vars[k] != null ? vars[k] : m));
    await sendTelegramNotification(env, settingsObj.telegramChatId, text);
  }

  return jsonResponse({ ok: true, order });
}

async function handleRequestCode(env) {
  const lastSent = await env.WO_KV.get("auth:lastSentAt");
  if (lastSent && Date.now() - Number(lastSent) < 60000) {
    return jsonResponse({ error: "Tunggu sebentar sebelum meminta kode baru." }, 429);
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await env.WO_KV.put("auth:otp", JSON.stringify({ code, attempts: 0 }), { expirationTtl: 300 });
  await env.WO_KV.put("auth:lastSentAt", String(Date.now()), { expirationTtl: 60 });

  try {
    const emailResp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Wo Admin <onboarding@resend.dev>",
        to: [env.ADMIN_EMAIL],
        subject: "Kode masuk Kelola Toko Wo",
        html: `<p>Kode verifikasi kamu:</p><p style="font-size:24px; font-weight:bold; letter-spacing:2px;">${code}</p><p>Berlaku 5 menit. Jangan bagikan kode ini ke siapa pun.</p>`
      })
    });
    if (!emailResp.ok) {
      const detail = await emailResp.text();
      return jsonResponse({ error: "Gagal mengirim email", detail }, 500);
    }
  } catch (e) {
    return jsonResponse({ error: "Gagal menghubungi layanan email." }, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleVerifyCode(request, env) {
  const body = await request.json().catch(() => ({}));
  const submitted = String(body.code || "").trim();

  const raw = await env.WO_KV.get("auth:otp");
  if (!raw) {
    return jsonResponse({ error: "Kode tidak ditemukan atau sudah kedaluwarsa." }, 400);
  }
  const record = JSON.parse(raw);

  if (record.attempts >= 5) {
    await env.WO_KV.delete("auth:otp");
    return jsonResponse({ error: "Terlalu banyak percobaan salah. Minta kode baru." }, 429);
  }

  if (submitted !== record.code) {
    record.attempts += 1;
    await env.WO_KV.put("auth:otp", JSON.stringify(record), { expirationTtl: 300 });
    return jsonResponse({ error: "Kode salah." }, 401);
  }

  await env.WO_KV.delete("auth:otp");
  const token = crypto.randomUUID();
  // OTP always goes to ADMIN_EMAIL, so an OTP-verified session always belongs to the owner.
  await env.WO_KV.put("auth:session:" + token, env.ADMIN_EMAIL, { expirationTtl: 60 * 60 * 24 });
  return jsonResponse({ ok: true, token, email: env.ADMIN_EMAIL, isOwner: true, name: "", outletAccess: "all", tabs: VALID_TABS.slice(), canEditOrder: true, canEditStatus: true });
}

async function handlePasswordLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !password) {
    return jsonResponse({ error: "Email dan kata sandi wajib diisi." }, 400);
  }

  const adminsRaw = await env.WO_KV.get("wo:admins");
  const admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  const account = admins.find(a => a.email.toLowerCase() === email);
  if (!account) {
    return jsonResponse({ error: "Email atau kata sandi salah." }, 401);
  }

  const hash = await hashPassword(password, account.passwordSalt);
  if (!timingSafeEqual(hash, account.passwordHash)) {
    return jsonResponse({ error: "Email atau kata sandi salah." }, 401);
  }

  const token = crypto.randomUUID();
  await env.WO_KV.put("auth:session:" + token, account.email, { expirationTtl: 60 * 60 * 24 });
  const isOwner = isOwnerEmail(account.email, env);
  const normalized = isOwner ? null : normalizeAdminForResponse(account);
  return jsonResponse({
    ok: true,
    token,
    email: account.email,
    name: account.name || "",
    isOwner,
    outletAccess: normalized ? normalized.outletAccess : "all",
    tabs: normalized ? normalized.tabs : VALID_TABS.slice(),
    canEditOrder: normalized ? normalized.canEditOrder : true,
    canEditStatus: normalized ? normalized.canEditStatus : true
  });
}

async function handleListAdmins(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!isOwnerEmail(sessionEmail, env)) {
    return jsonResponse({ error: "Hanya pemilik akun yang bisa mengelola admin." }, 403);
  }
  const adminsRaw = await env.WO_KV.get("wo:admins");
  const admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  return jsonResponse({ ok: true, admins: admins.map(a => normalizeAdminForResponse(a)) });
}

// Accounts created before granular permissions existed only have the old
// role: "general"|"regular" field. This maps that to the new shape so
// nobody's access silently changes when the UI switches over.
function normalizeAdminForResponse(a) {
  if (a.tabs != null) {
    return {
      email: a.email, name: a.name || "",
      outletAccess: a.outletAccess || "all",
      tabs: a.tabs || [],
      canEditOrder: a.canEditOrder !== false,
      canEditStatus: a.canEditStatus !== false
    };
  }
  const isGeneral = (a.role || "general") !== "regular";
  return {
    email: a.email, name: a.name || "",
    outletAccess: "all",
    tabs: isGeneral ? ["orders", "dashboard", "items", "outlet", "messages", "settings"] : ["orders"],
    canEditOrder: isGeneral,
    canEditStatus: true
  };
}

const VALID_TABS = ["orders", "dashboard", "items", "outlet", "messages", "settings"];

async function handleRegisterAdmin(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!isOwnerEmail(sessionEmail, env)) {
    return jsonResponse({ error: "Hanya pemilik akun yang bisa menambah admin." }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const newEmail = String(body.email || "").trim().toLowerCase();
  const name = String(body.name || "").trim().slice(0, 100);
  const password = String(body.password || "");
  const outletAccess = String(body.outletAccess || "all");
  const tabs = Array.isArray(body.tabs) ? body.tabs.filter(t => VALID_TABS.includes(t)) : [];
  const canEditOrder = !!body.canEditOrder;
  const canEditStatus = !!body.canEditStatus;
  if (!newEmail || !password) {
    return jsonResponse({ error: "Email dan kata sandi wajib diisi." }, 400);
  }
  if (password.length < 8) {
    return jsonResponse({ error: "Kata sandi minimal 8 karakter." }, 400);
  }

  const adminsRaw = await env.WO_KV.get("wo:admins");
  const admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  if (admins.some(a => a.email.toLowerCase() === newEmail)) {
    return jsonResponse({ error: "Email ini sudah terdaftar." }, 400);
  }

  const salt = generateSalt();
  const hash = await hashPassword(password, salt);
  admins.push({ email: newEmail, name, passwordSalt: salt, passwordHash: hash, outletAccess, tabs, canEditOrder, canEditStatus });
  await env.WO_KV.put("wo:admins", JSON.stringify(admins));
  return jsonResponse({ ok: true });
}

async function handleUpdateAdmin(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!isOwnerEmail(sessionEmail, env)) {
    return jsonResponse({ error: "Hanya pemilik akun yang bisa mengubah admin." }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const targetEmail = String(body.email || "").trim().toLowerCase();
  if (!targetEmail) return jsonResponse({ error: "Email tidak valid." }, 400);
  if (isOwnerEmail(targetEmail, env)) {
    return jsonResponse({ error: "Akun pemilik tidak diatur lewat sini." }, 400);
  }

  const adminsRaw = await env.WO_KV.get("wo:admins");
  const admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  const account = admins.find(a => a.email.toLowerCase() === targetEmail);
  if (!account) return jsonResponse({ error: "Admin tidak ditemukan." }, 404);

  if (body.newEmail != null) {
    const newEmail = String(body.newEmail).trim().toLowerCase();
    if (!newEmail) return jsonResponse({ error: "Email tidak boleh kosong." }, 400);
    if (isOwnerEmail(newEmail, env)) {
      return jsonResponse({ error: "Email ini sudah dipakai akun pemilik." }, 400);
    }
    if (newEmail !== targetEmail && admins.some(a => a.email.toLowerCase() === newEmail)) {
      return jsonResponse({ error: "Email ini sudah dipakai admin lain." }, 400);
    }
    account.email = newEmail;
  }
  if (body.name != null) {
    account.name = String(body.name).trim().slice(0, 100);
  }
  if (body.outletAccess != null) {
    account.outletAccess = String(body.outletAccess || "all");
  }
  if (body.tabs != null) {
    account.tabs = Array.isArray(body.tabs) ? body.tabs.filter(t => VALID_TABS.includes(t)) : [];
  }
  if (body.canEditOrder != null) {
    account.canEditOrder = !!body.canEditOrder;
  }
  if (body.canEditStatus != null) {
    account.canEditStatus = !!body.canEditStatus;
  }
  delete account.role; // fully migrated off the old binary role field
  if (body.password) {
    const password = String(body.password);
    if (password.length < 8) {
      return jsonResponse({ error: "Kata sandi baru minimal 8 karakter." }, 400);
    }
    const salt = generateSalt();
    account.passwordSalt = salt;
    account.passwordHash = await hashPassword(password, salt);
  }

  await env.WO_KV.put("wo:admins", JSON.stringify(admins));
  return jsonResponse({ ok: true });
}

async function handleRemoveAdmin(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!isOwnerEmail(sessionEmail, env)) {
    return jsonResponse({ error: "Hanya pemilik akun yang bisa menghapus admin." }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const targetEmail = String(body.email || "").trim().toLowerCase();
  const adminsRaw = await env.WO_KV.get("wo:admins");
  let admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  admins = admins.filter(a => a.email.toLowerCase() !== targetEmail);
  await env.WO_KV.put("wo:admins", JSON.stringify(admins));
  return jsonResponse({ ok: true });
}

async function handleChangePassword(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!sessionEmail) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = await request.json().catch(() => ({}));
  const currentPassword = String(body.currentPassword || "");
  const newPassword = String(body.newPassword || "");
  if (!newPassword || newPassword.length < 8) {
    return jsonResponse({ error: "Kata sandi baru minimal 8 karakter." }, 400);
  }

  const adminsRaw = await env.WO_KV.get("wo:admins");
  let admins = adminsRaw ? JSON.parse(adminsRaw) : [];
  const idx = admins.findIndex(a => a.email.toLowerCase() === sessionEmail.toLowerCase());

  if (idx < 0) {
    // No password account yet for this session's email. Only the owner can reach this
    // state (via OTP login), and this doubles as the one-time "set up your password" step.
    if (!isOwnerEmail(sessionEmail, env)) {
      return jsonResponse({ error: "Akun tidak ditemukan." }, 404);
    }
    const salt = generateSalt();
    const hash = await hashPassword(newPassword, salt);
    admins.push({ email: sessionEmail, name: "", passwordSalt: salt, passwordHash: hash });
    await env.WO_KV.put("wo:admins", JSON.stringify(admins));
    return jsonResponse({ ok: true, created: true });
  }

  const currentHash = await hashPassword(currentPassword, admins[idx].passwordSalt);
  if (!timingSafeEqual(currentHash, admins[idx].passwordHash)) {
    return jsonResponse({ error: "Kata sandi saat ini salah." }, 401);
  }
  const salt = generateSalt();
  const hash = await hashPassword(newPassword, salt);
  admins[idx].passwordSalt = salt;
  admins[idx].passwordHash = hash;
  await env.WO_KV.put("wo:admins", JSON.stringify(admins));
  return jsonResponse({ ok: true });
}

async function deleteAllByPrefix(env, prefix) {
  let cursor = undefined;
  let count = 0;
  do {
    const listResult = await env.WO_KV.list({ prefix, cursor });
    for (const key of listResult.keys) {
      await env.WO_KV.delete(key.name);
      count++;
    }
    cursor = listResult.list_complete ? undefined : listResult.cursor;
  } while (cursor);
  return count;
}

async function handleResetOrders(request, env) {
  const sessionEmail = await getSessionEmail(request, env);
  if (!isOwnerEmail(sessionEmail, env)) {
    return jsonResponse({ error: "Hanya pemilik akun yang bisa mereset data pesanan." }, 403);
  }
  // Deleting by prefix (rather than walking each outlet's index) catches every
  // order/index/quota key regardless of outlet, including any that might exist
  // outside a tracked index. Invoice numbers are derived from the order-ids
  // index length at creation time, so clearing it makes the next order start
  // back at 0001 automatically — no separate counter to reset.
  const deletedOrders = await deleteAllByPrefix(env, "wo:order:");
  const deletedIndexes = await deleteAllByPrefix(env, "wo:order-ids:");
  const deletedQuota = await deleteAllByPrefix(env, "wo:preorder-usage:");
  return jsonResponse({ ok: true, deletedOrders, deletedIndexes, deletedQuota });
}

async function expireOverdueOrders(env) {
  const settingsRaw = await env.WO_KV.get("wo:settings");
  const settings = settingsRaw ? JSON.parse(settingsRaw) : {};
  const outlets = Array.isArray(settings.outlets) ? settings.outlets : [];
  const now = Date.now();

  for (const outlet of outlets) {
    const idxRaw = await env.WO_KV.get("wo:order-ids:" + outlet.id);
    if (!idxRaw) continue;
    const ids = JSON.parse(idxRaw);
    for (const id of ids) {
      const raw = await env.WO_KV.get("wo:order:" + id);
      if (!raw) continue;
      const order = JSON.parse(raw);
      if (
        order.status === "unpaid" &&
        order.paymentDeadline &&
        now > new Date(order.paymentDeadline).getTime()
      ) {
        order.status = "failed";

        // Release any pre-order quota this failed order was holding —
        // guarded so it never double-releases (e.g. if an admin already
        // manually marked it failed and released it before the cron ran).
        if (order.orderType === "preorder" && !order.quotaReleased) {
          const totalQty = (order.items || []).reduce((s, i) => s + (Number(i.qty) || 0), 0);
          const half = halfForTime(order.deliveryTime);
          const used = await getQuotaUsage(env, order.outlet, order.deliveryDate, half);
          await env.WO_KV.put(quotaKey(order.outlet, order.deliveryDate, half), String(Math.max(0, used - totalQty)));
          order.quotaReleased = true;
        }

        await env.WO_KV.put("wo:order:" + id, JSON.stringify(order));
      }
    }
  }
}
