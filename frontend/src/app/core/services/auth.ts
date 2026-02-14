import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
@Injectable({
  providedIn: 'root',
})
export class Auth {
  private baseUrl = environment.apiUrl;
  constructor(private http: HttpClient) { }
  testConnection() {
    return this.http.get(`${this.baseUrl}/test`);
  }
}
