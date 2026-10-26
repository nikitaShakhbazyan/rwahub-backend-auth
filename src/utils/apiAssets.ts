import { API_BASE_URL } from '@/utils/apiBase';
import { authHeaders } from '@/utils/authToken';

/** An API failure that keeps the HTTP status, so callers can react to a 401. */
export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function normalizeAsset(raw: any) {
  const priceAmount = Number(raw?.price?.amount ?? raw?.value ?? 0);
  return {
    ...raw,
    imageUrl: raw?.imageUrl || raw?.images?.[0] || '',
    value: Number.isFinite(Number(raw?.value)) ? Number(raw.value) : priceAmount,
    views: raw?.views ?? 0,
    likes: raw?.likes ?? 0,
    tokenId: raw?.tokenId || raw?.id || '',
    createdAt: raw?.createdAt ? new Date(raw.createdAt) : new Date(),
    updatedAt: raw?.updatedAt ? new Date(raw.updatedAt) : new Date(),
    price: {
      amount: Number.isFinite(priceAmount) ? priceAmount : 0,
      currency: raw?.price?.currency || 'USDT',
    },
  };
}

export async function fetchAssetsFromApi(params?: Record<string, string | number | undefined>) {
  const query = new URLSearchParams();
  query.set('limit', String(params?.limit ?? 100));
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && key !== 'limit') {
      query.set(key, String(value));
    }
  });
  const response = await fetch(`${API_BASE_URL}/assets?${query.toString()}`);
  if (!response.ok) {
    throw new Error('Failed to fetch assets');
  }
  const data = await response.json();
  const assets = Array.isArray(data?.assets) ? data.assets : Array.isArray(data) ? data : [];
  return assets.map(normalizeAsset);
}

export async function fetchAssetByIdFromApi(id: string) {
  const response = await fetch(`${API_BASE_URL}/assets/${encodeURIComponent(id)}`);
  if (!response.ok) {
    throw new Error('Failed to fetch asset');
  }
  return normalizeAsset(await response.json());
}

export async function createAssetOnApi(asset: any) {
  const description = String(asset.description || '');
  const payload = {
    title: asset.title,
    description: description.length >= 10 ? description : `${description} tokenized asset`.trim(),
    category: asset.category || 'other',
    price: asset.price,
    tokenization: asset.tokenization,
    listingType: asset.listingType || 'fixed',
    imageUrl: typeof asset.imageUrl === 'string' && asset.imageUrl.startsWith('http')
      ? asset.imageUrl
      : 'https://images.pexels.com/photos/9978722/pexels-photo-9978722.jpeg',
    images: Array.isArray(asset.images) ? asset.images.filter((url: string) => typeof url === 'string' && url.startsWith('http')) : [],
    tokenId: asset.tokenId,
    value: asset.value ?? asset.price?.amount,
  };

  const response = await fetch(`${API_BASE_URL}/assets`, {
    method: 'POST',
    // The server derives the owner from this token. Note that `owner` is no
    // longer sent: the API ignores it, and sending it would imply otherwise.
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(
      body?.error || 'Failed to create asset',
      response.status,
      body?.code
    );
  }

  return normalizeAsset(await response.json());
}
