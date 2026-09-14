"""Exact tool binding for the observed VendorPayment Gateway schema."""
from ..cedar import compile_exact_scope_permit

def compile_payment_permit(**kwargs):
    return compile_exact_scope_permit(**kwargs,tool_name='prepare_vendor_payment',
        input_name='payment_request_id',compiler_id='authority-delta-finite-payment-v1')
