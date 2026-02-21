import { CanActivateFn, Router } from '@angular/router';
import { Auth } from '../services/auth';
import { inject } from '@angular/core';
import { catchError, map, of } from 'rxjs';

export const guestGuard: CanActivateFn = (route, state) => {
  const authService = inject(Auth);
  const router = inject(Router);

  return authService.profile().pipe(
    map(() => {
      router.navigateByUrl('/dashboard');
      return false;
    }),
    catchError(() => of(true))
  );
};
