<?php

Route::post('/checkout', function ($request) {
    $email = $request->input('email_address');
    $upi = $request->input('upi_id');
    Log::info('checkout upi ' . $upi);
    Order::create(['email_address' => $email, 'upi_id' => $upi]);
});
