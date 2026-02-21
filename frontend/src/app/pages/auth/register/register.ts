import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Auth } from '../../../core/services/auth';

@Component({
  selector: 'app-register',
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './register.html',
  styleUrl: './register.css',
})
export class Register implements OnInit{

  registerForm!: FormGroup;
  loading = false;
  message = '';
  error = '';

  constructor(
    private authService: Auth,
    private fb: FormBuilder,
  ) { }

  createRegisterForm() {
    this.registerForm = this.fb.group({
      name: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]]
    });
  }

  ngOnInit(): void {
    this.createRegisterForm()
  }

   onSubmit() {
    if (this.registerForm.invalid) return;

    this.loading = true;
    this.error = '';
    this.message = '';

    this.authService.register(this.registerForm.value).subscribe({
      next: (res) => {
        this.message = res.message;
        this.loading = false;
      },
      error: (err) => {
        this.error = err.error?.message || 'Something went wrong';
        this.loading = false;
      }
    });
  }
}
