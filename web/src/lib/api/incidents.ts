import { get, post } from "./client";
import type { Paged, Incident, IncidentDetail } from "./types";

export const incidentsApi = {
  list: (params: { page: number; page_size: number; status?: string; host_id?: string }) =>
    get<Paged<Incident>>("/incidents", params),
  get: (id: string) => get<IncidentDetail>(`/incidents/${id}`),
  resolve: (id: string) => post(`/incidents/${id}/resolve`),
};
