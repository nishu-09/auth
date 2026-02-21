import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth-guard';
import { guestGuard } from './core/guards/guest-guard';

export const routes: Routes = [
    // Default path
    {
        path: '',
        redirectTo: 'login',
        pathMatch: 'full'
    },
    {
        path: 'login',
        canActivate: [guestGuard],
        loadComponent: () =>
            import('../app/pages/auth/login/login').then(m => m.Login)
    },
     {
        path: 'register',
        canActivate: [guestGuard],
        loadComponent: () =>
            import('../app/pages/auth/register/register').then(m => m.Register)
    },
     {
        path: 'home',
        canActivate: [authGuard],
        loadComponent: () =>
            import('../app/pages/dashboard/dashboard').then(m => m.Dashboard)
    },
];
