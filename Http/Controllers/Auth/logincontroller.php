<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;

use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Socialite;

use Auth;

use Exception;

use App\User;

class logincontroller extends Controller

{

    use AuthenticatesUsers;

    public function __construct()

    {

        $this->middleware('guest')->except('logout');

    }

    public function redirectToGoogle()

    {

        return Socialite::driver('google')->redirect();

    }

    public function handleGoogleCallback()

    {

        try {

            $user = Socialite::driver('google')->user();

            $finduser = User::where('google_id', $user->id)->first();

            if($finduser){

                Auth::login($finduser);

             return redirect('/home');

            }else{

                $newUser = User::create([

                    'name' => $user->name,

                    'email' => $user->email,

              'google_id'=> $user->id

                ]);

                Auth::login($newUser);

                return redirect()->back();

            }

        } catch (Exception $e) {

            return redirect('auth/google');

        }

    }

}