import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { Auth } from '../services/auth';
import { catchError, map, of } from 'rxjs';

export const authGuard: CanActivateFn = (route, state) => {

  const authService = inject(Auth);
  const router = inject(Router);

  return authService.profile().pipe(
    map(() => true), // if profile works → user authenticated
    catchError(() => {
      router.navigateByUrl('/login');
      return of(false);
    })
  );

};
