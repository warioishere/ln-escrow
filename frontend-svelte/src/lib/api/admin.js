import { request, adminHeaders } from './_shared.js';

export async function getAdminConfig(pubkey) {
	return request('/deals/admin/config', {
		headers: adminHeaders(null, pubkey)
	});
}

export async function getAdminDeals(pubkey, includeFinished = false, limit = 100) {
	return request(`/deals/admin/deals?include_finished=${includeFinished}&limit=${limit}`, {
		headers: adminHeaders(null, pubkey)
	});
}

export async function getAdminDisputes(pubkey) {
	return request('/deals/admin/disputes', {
		headers: adminHeaders(null, pubkey)
	});
}

export async function getAdminFailedPayouts(pubkey) {
	return request('/deals/admin/failed-payouts', {
		headers: adminHeaders(null, pubkey)
	});
}

export async function getAdminLedger(pubkey) {
	return request('/deals/admin/ledger', {
		headers: adminHeaders(null, pubkey)
	});
}

export async function adminResolveRelease(dealId, pubkey, note = null) {
	return request(`/deals/admin/${dealId}/resolve-release`, {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify({ resolution_note: note })
	});
}

export async function adminResolveRefund(dealId, pubkey, note = null) {
	return request(`/deals/admin/${dealId}/resolve-refund`, {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify({ resolution_note: note })
	});
}

export async function adminOracleSign(dealId, pubkey, signedEvent) {
	return request(`/deals/admin/${dealId}/oracle-sign`, {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify({ signed_event: signedEvent })
	});
}

export async function getLimits() {
	return request('/deals/settings/limits');
}

export async function updateLimits(pubkey, minSats, maxSats) {
	const body = {};
	if (minSats !== undefined && minSats !== null) body.min_sats = minSats;
	if (maxSats !== undefined && maxSats !== null) body.max_sats = maxSats;

	return request('/deals/admin/settings/limits', {
		method: 'PUT',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify(body)
	});
}

export async function updateFees(pubkey, serviceFeePercent) {
	const body = {};
	if (serviceFeePercent !== undefined && serviceFeePercent !== null) body.service_fee_percent = serviceFeePercent;

	return request('/deals/admin/settings/fees', {
		method: 'PUT',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify(body)
	});
}

export async function searchDeals(pubkey, params = {}) {
	const query = new URLSearchParams();
	if (params.title) query.set('title', params.title);
	if (params.status) query.set('status_filter', params.status);
	if (params.minSats) query.set('min_sats', params.minSats);
	if (params.maxSats) query.set('max_sats', params.maxSats);
	if (params.createdAfter) query.set('created_after', params.createdAfter);
	if (params.createdBefore) query.set('created_before', params.createdBefore);
	if (params.limit) query.set('limit', params.limit);
	return request(`/deals/search?${query}`, {
		headers: adminHeaders(null, pubkey)
	});
}

export async function adminBulkResolve(pubkey, dealIds, resolution, note = null) {
	return request('/deals/admin/bulk/resolve', {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify({ deal_ids: dealIds, resolution, resolution_note: note })
	});
}

export async function adminBulkRetryPayouts(pubkey, dealIds = null) {
	return request('/deals/admin/bulk/retry-payouts', {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify(dealIds ? { deal_ids: dealIds } : {})
	});
}

export async function adminRegisterWebhook(pubkey, url, secret = null, events = null) {
	return request('/deals/admin/webhooks', {
		method: 'POST',
		headers: adminHeaders(null, pubkey),
		body: JSON.stringify({ url, secret, events })
	});
}

export async function adminListWebhooks(pubkey) {
	return request('/deals/admin/webhooks', {
		headers: adminHeaders(null, pubkey)
	});
}

export async function adminDeleteWebhook(pubkey, webhookId) {
	return request(`/deals/admin/webhooks/${webhookId}`, {
		method: 'DELETE',
		headers: adminHeaders(null, pubkey)
	});
}

export async function getAdminChallenge() {
	return request('/auth/lnurl/admin/challenge');
}

export async function checkAdminAuthStatus(k1) {
	return request(`/auth/lnurl/admin/status/${k1}`);
}
