import { request } from './_shared.js';

export async function createDeal(data) {
	return request('/deals/', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export async function getDeal(id) {
	return request(`/deals/${id}`);
}

export async function getDealByToken(token) {
	return request(`/deals/token/${token}`);
}

export async function getSigningStatus(dealId) {
	return request(`/deals/${dealId}/signing-status`);
}

export async function deleteDeal(dealId, userId, signature, timestamp) {
	return request(`/deals/${dealId}`, {
		method: 'DELETE',
		body: JSON.stringify({ user_id: userId, signature, timestamp })
	});
}

export async function getPayoutStatus(dealId) {
	return request(`/deals/${dealId}/payout-status`);
}

