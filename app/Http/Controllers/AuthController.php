<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function signup(Request $request)
    {
       
        // Authentication
        $validate = Validator::make(
            $request->all(),
            [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required'
            ]
        );
    
        // response after validation
        if ($validate->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Validation failed',
                'errors' => $validate->errors()->all()
            ]);
        }
        // Create data in database
        
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'remember_token'=>$request->remember_token,
        ]);
    
    
        return response()->json([
            'status' => true,
            'message' => 'User created successfully',
            'user' => $user,
            // 'token'=>$user->createToken("API TOKEN")->plainTextToken
            // 'token'=>$user->remember_token->createToken('Api Token')
        ], 200);
    }
    


    public function login(Request $request)
{
    
    $validate = Validator::make(
        $request->all(),
        [
            'email' => 'required|email',  
            'password' => 'required'
        ]
    );

   
    if ($validate->fails()) {
        return response()->json([
            'status' => false,
            'message' => 'Authentication Failed',
            'errors' => $validate->errors()->all()
        ], 401);
    }

    
    if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
        // dd($request);
        $auth = Auth::user();  
        $user = User::where('email',$request->email)->first();   
        $user->remember_token=$auth->createToken("API TOKEN")->plainTextToken;
        $user->save();
        return response()->json([
            'status' => true,
            'message' => 'Authenticated',
            'token' => $auth->createToken("API TOKEN")->plainTextToken,  
            'token_type' => 'bearer'
        ], 200);
    } else {
       
        return response()->json([
            'status' => false,
            'message' => 'Email and Password do not match',
        ], 401);
    }



}

    public function logout(Request $request)
    {
        $user=$request->user();
        $user->tokens()->delete();


        return response()->json([
            'status'=>true,
            'message'=>'Logout Succesfuuly',
            'user'=>$user
        ],200);
    }

}
