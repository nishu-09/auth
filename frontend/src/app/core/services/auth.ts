import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
}
export interface LoginPayload {
  email: string;
  password: string;
}

export interface ApiResponse {
  success: boolean;
  message: string;
}

@Injectable({
  providedIn: 'root',
})
export class Auth {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) { }

  register(payload: RegisterPayload): Observable<ApiResponse> {
    return this.http.post<ApiResponse>(`${this.apiUrl}/auth/register`, payload, {
      withCredentials: true //  uwhile sing cookies
    });
  }

  login(payload: LoginPayload): Observable<any> {
    return this.http.post(`${this.apiUrl}/auth/login`, payload, {
      withCredentials: true
    });
  }

  profile(): Observable<any> {
    return this.http.get(`${this.apiUrl}/auth/profile`)
  }
}
