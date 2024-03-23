<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\User;
use config\auth;
use config\Hashing;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function index(){

        return view('main');
    }

    public function create(Request $request)
    {
        $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'phonenumber'=>'required|integer|min:10|unique:users',
        'dob'=>'required|string|max:255',
        'password' => 'required|string|min:8|confirmed',
        
            
    ]);
    if ($validator->fails())
    {
        return response(['errors'=>$validator->errors()->all()], 422);
    }
       
        User::create([
            'name'=> $request->name,
            'email'=> $request->email,
            'phonenumber'=> $request->phonenumber,
            'dob'=>$request->dob,
            'password' => Hash::make($request->password),
        ]);
        
        return redirect('main');
    }

    
    public function authentication (Request $request)
    {
        

        
        $request->validate([
            'email' => 'required|string|email',
            'phonenumber'=>'required|integer|phonenumber',
            'password' => 'required|min:8',

        ]);
        $credentials = $request->only('email','phonenumber','password');

        if(Auth::attempt($credentials)){
            return redirect()->intended('index');
        }
        return redirect('index')->with('error', 'Oopes! You have entered invalid credentials');
     
    }

    public function logout(){
        Auth::logout();
        return redirect('main');
    }
    

    public function api_register (Request $request) {
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'phonenumber'=>'required|integer|min:10|unique:users',
        'dob'=>'required|string|max:255',
        'password' => 'required|string|min:8|confirmed',
        
            
    ]);
    if ($validator->fails())
    {
        return response(['errors'=>$validator->errors()->all()], 422);
    }
    $request['password']=Hash::make($request['password']);
    $request['remember_token'] = Str::random(10);
    $user = User::create($request->toArray());
    $token = $user->createToken('Laravel Password Grant Client')->accessToken;
    $response = ['token' => $token];
    return response($response, 200);
}



public function api_login (Request $request) {
    $validator = Validator::make($request->all(), [
        'email' => 'required|string|email|max:255',
        'password' => 'required|string|min:6|confirmed',
    ]);
    if ($validator->fails())
    {
        return response(['errors'=>$validator->errors()->all()], 422);
    }
    $user = User::where('email', $request->email)->first();
    if ($user) {
        if (Hash::check($request->password, $user->password)) {
            $token = $user->createToken('Laravel Password Grant Client')->accessToken;
            $response = ['token' => $token];
            return response($response, 200);
        } else {
            $response = ["message" => "Password mismatch"];
            return response($response, 422);
        }
    } else {
        $response = ["message" =>'User does not exist'];
        return response($response, 422);
    }
}

public function api_logout (Request $request) {
    $token = $request->user()->token();
    $token->revoke();
    $response = ['message' => 'You have been successfully logged out!'];
    return response($response, 200);
}
}
