
import { DataProvider, fetchUtils } from 'react-admin';
import { authProvider } from './authProvider';

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:3001';

const httpClient: fetchUtils.HttpClient = async (url, options = {}) => {
  await authProvider.checkAuth();
  const { accessToken } = JSON.parse(localStorage.getItem('tokens')!);
  options.user = {
    authenticated: true,
    token: `${accessToken}`,
  };
  return fetchUtils.fetchJson(url, options);
};

export const dataProvider: DataProvider = {
  getList: async (resource, params) => {
    const { page, perPage } = params.pagination;
    const { field, order } = params.sort;

    const query = fetchUtils.queryParameters({
      _start: (page - 1) * perPage,
      _end: page * perPage,
      _sort: field,
      _order: order,
      ...fetchUtils.flattenObject(params.filter),
    });

    const url = `${API}/${resource}?${query}`;
    const res = await httpClient(url);

    return {
      data: res.json as any[], // ✅ actual array
      total: parseInt(res.headers.get('X-Total-Count') || '0', 10),
    };
  },

  getOne: (resource, { id }) =>
    httpClient(`${API}/${resource}/${id}`).then(({ json }) => ({ data: json })),

  create: (resource, { data }) =>
    httpClient(`${API}/${resource}`, {
      method: 'POST',
      body: JSON.stringify(data),
    }).then(({ json }) => ({ data: json })),

  update: (resource, { id, data }) =>
    httpClient(`${API}/${resource}/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }).then(({ json }) => ({ data: json })),

  delete: (resource, { id }) =>
    httpClient(`${API}/${resource}/${id}`, {
      method: 'DELETE',
    }).then(() => ({ data: { id } })),
};
