import { HttpClient, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Router } from '@angular/router';

let isRefreshing = false;

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const http = inject(HttpClient);
  const router = inject(Router);
  const apiUrl = environment.apiUrl;

  const clonedReq = req.clone({ withCredentials: true });

  return next(clonedReq).pipe(
    catchError((error) => {

      if (
        error.status === 401 &&
        !req.url.includes('/refresh') &&
        !isRefreshing
      ) {

        isRefreshing = true;

        return http.post(
          `${apiUrl}/auth/refresh`,
          {},
          { withCredentials: true }
        ).pipe(
          switchMap(() => {
            isRefreshing = false;

            // Retry ORIGINAL request (profile will be called again)
            return next(clonedReq);
          }),
          catchError((refreshError) => {
            isRefreshing = false;

            // Only redirect if refresh fails
            router.navigateByUrl('/login');

            return throwError(() => refreshError);
          })
        );
      }

      return throwError(() => error);
    })
  );
};
