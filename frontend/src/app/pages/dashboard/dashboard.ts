import { Component, OnInit } from '@angular/core';
import { Auth } from '../../core/services/auth';

@Component({
  selector: 'app-dashboard',
  imports: [],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit{

  constructor(private authService:Auth){}
  ngOnInit(): void {
    this.getFrofileData()
  }
  getFrofileData(){
    this.authService.profile().subscribe((res:any)=>{
   
    })
  }
}
