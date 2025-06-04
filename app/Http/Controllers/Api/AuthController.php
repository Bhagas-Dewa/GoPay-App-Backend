<?php

namespace App\Http\Controllers\Api;

use App\Models\OtpCode;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use App\Mail\OtpMail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    // 1. Cek apakah email sudah terdaftar (LOGIN)
    public function checkEmailForLogin(Request $request)
    {
        $request->validate(['email' => 'required|email']);
        $user = User::where('email', $request->email)->first();

        if ($user) {
            return response()->json([
                'status' => 'registered',
                'message' => 'Email terdaftar. Silakan lanjut ke input PIN.'
            ]);
        }

        return response()->json([
            'status' => 'not_found',
            'message' => 'Email belum terdaftar.'
        ], 404);
    }

    // 2. Login dengan PIN
    public function loginWithPin(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'pin_code' => 'required|digits:6'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->pin_code, $user->pin_code)) {
            return response()->json([
                'status' => 'unauthorized',
                'message' => 'Email atau PIN salah.'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'message' => 'Login berhasil.',
            'token' => $token,
            'user' => $user->only(['id', 'name', 'email'])
        ]);
    }

    // 3. Cek email untuk REGISTER dan kirim OTP
    public function checkEmailForRegister(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        if (User::where('email', $request->email)->exists()) {
            return response()->json([
                'status' => 'used',
                'message' => 'Email sudah digunakan. Silakan login atau gunakan email lain.'
            ], 422);
        }

        $otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);

        try {
            OtpCode::updateOrCreate(
                ['email' => $request->email],
                [
                    'otp_code' => bcrypt($otp), // Menggunakan bcrypt untuk hash OTP
                    'expires_at' => Carbon::now()->addMinutes(10),
                    'is_verified' => false
                ]
            );

            Mail::to($request->email)->send(new OtpMail($otp));

            return response()->json([
                'status' => 'otp_sent',
                'message' => 'OTP berhasil dikirim ke email Anda.',
                'expires_in' => 10
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to send OTP: ' . $e->getMessage());

            return response()->json([
                'status' => 'error',
                'message' => 'Gagal mengirim OTP. Silakan coba lagi.'
            ], 500);
        }
    }

    // 4. Verifikasi OTP
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp_code' => 'required|digits:6'
        ]);

        $otpEntry = OtpCode::where('email', $request->email)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$otpEntry || !Hash::check($request->otp_code, $otpEntry->otp_code)) {
            return response()->json([
                'status' => 'invalid',
                'message' => 'OTP salah atau sudah kadaluarsa.'
            ], 422);
        }

        $otpEntry->update([
            'is_verified' => true,
            'expires_at' => Carbon::now()->addMinutes(15) // perpanjang masa aktif setelah verifikasi
        ]);

        return response()->json([
            'status' => 'verified',
            'message' => 'OTP berhasil diverifikasi. Silakan isi nama.'
        ]);
    }

    // 5. Simpan Nama setelah OTP diverifikasi
    public function setName(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'name' => 'required|string|min:2|max:255',
        ]);

        $otp = OtpCode::where('email', $request->email)
            ->where('is_verified', true)
            ->first(); 

        if (!$otp) {
            return response()->json([
                'status' => 'otp_required',
                'message' => 'OTP belum diverifikasi.'
            ], 422);
        }

        $otp->update(['name' => trim($request->name)]);

        return response()->json([
            'status' => 'name_saved',
            'message' => 'Nama berhasil disimpan. Silakan lanjut membuat PIN.'
        ]);
    }

    // 6. Simpan PIN dan buat akun user
    public function setPin(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'pin_code' => 'required|digits:6',
        ]);

        $otp = OtpCode::where('email', $request->email)
            ->where('is_verified', true)
            ->first(); // tidak cek expires_at lagi

        if (!$otp || !$otp->name) {
            return response()->json([
                'status' => 'incomplete_data',
                'message' => 'Silakan isi nama terlebih dahulu.'
            ], 422);
        }

        if (User::where('email', $request->email)->exists()) {
            return response()->json([
                'status' => 'used',
                'message' => 'Email sudah digunakan. Silakan login.'
            ], 422);
        }

        try {
            DB::beginTransaction();

            $user = User::create([
                'name' => $otp->name,
                'email' => $request->email,
                'pin_code' => bcrypt($request->pin_code), // Menggunakan bcrypt untuk hash PIN
                'email_verified_at' => Carbon::now()
            ]);

            $otp->delete();

            $token = $user->createToken('auth_token')->plainTextToken;

            DB::commit();

            return response()->json([
                'status' => 'registered',
                'message' => 'Registrasi berhasil.',
                'token' => $token,
                'user' => $user->only(['id', 'name', 'email'])
            ], 201);
        } catch (\Exception $e) {
            DB::rollBack();
            Log::error('Register Error: ' . $e->getMessage());

            return response()->json([
                'status' => 'error',
                'message' => 'Terjadi kesalahan saat registrasi.'
            ], 500);
        }
    }

    public function me(Request $request)
    {
        return response()->json([
            'status' => 'success',
            'message' => 'Data pengguna berhasil diambil.',
            'data' => $request->user(),
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Logout berhasil.',
        ]);
    }
}