#!/usr/bin/perl
#https://www.ietf.org/proceedings/52/slides/ipsec-9.pdf
#sigma_i

use strict;
use warnings;

#use lib '../lib';

use bignum;
use Smart::Comments;

use Test::More;
use FindBin qw($Bin);

use CBOR::XS;

use Crypt::SIGMA;

use Crypt::KeyDerivation ':all';
use Digest::SHA qw/hmac_sha256/;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

use Crypt::OpenSSL::Hash2Curve;
use Crypt::OpenSSL::Base::Func;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::ECDSA;

my $random_range     = Crypt::OpenSSL::Bignum->new_from_hex( join( "", ( 'f' ) x 32 ) );
my $iv_range         = Crypt::OpenSSL::Bignum->new_from_hex( join( "", ( 'f' ) x 24 ) );
my $group_name       = 'prime256v1';
my $key_len          = 32;
my $hash_name        = 'SHA256';
my $cipher_name      = 'AES';
my $point_compress_t = 2;

my $enc_func = sub {
  my ( $ke, $plaintext, $pack_msg_func ) = @_;
  my $iv = Crypt::OpenSSL::Bignum->rand_range( $iv_range );
  my ( $ciphertext, $tag ) = gcm_encrypt_authenticate( $cipher_name, $ke, $iv->to_bin, undef, $plaintext );

  my $cipher_info = $pack_msg_func->( [ $iv->to_bin, $ciphertext, $tag ] );
  ### iv: $iv->to_hex
  ### ciphertext: unpack("H*", $ciphertext)
  ### tag: unpack("H*", $tag)
  ### cipher_info: unpack("H*", $cipher_info)
  return $cipher_info;
};

my $dec_func = sub {
  my ( $ke, $iv, $ciphertext, $tag ) = @_;
  my $plaintext = gcm_decrypt_verify( 'AES', $ke, $iv, undef, $ciphertext, $tag );
  ### iv: unpack("H*", $iv)
  ### ciphertext: unpack("H*", $ciphertext)
  ### tag: unpack("H*", $tag)
  ### plaintext: unpack("H*", $plaintext)
  return $plaintext;
};

my $mac_func = sub {
  my ( $km, $data ) = @_;
  return hmac_sha256( $data, $km );
};

my $sig_verify_func = sub {
  my ( $pkey_fname, $tbs, $r, $s ) = @_;

  my $a_know_b_s_pub_pkey = pem_read_pkey( $pkey_fname, 0 );
  my $a_know_b_s_pub      = EVP_PKEY_get1_EC_KEY( $a_know_b_s_pub_pkey );

  my $a_recv_sig = Crypt::OpenSSL::ECDSA::ECDSA_SIG->new();
  $a_recv_sig->set_r( $r );
  $a_recv_sig->set_s( $s );

  my $a_verify = Crypt::OpenSSL::ECDSA::ECDSA_do_verify( $tbs, $a_recv_sig, $a_know_b_s_pub );
  ### verify sig : $a_verify
  return $a_verify;
};

my $sign_func = sub {
  my ( $pkey_fname, $b_tbs ) = @_;
  my $b_s_priv_pkey = pem_read_pkey( $pkey_fname, 1 );
  my $b_s_priv      = EVP_PKEY_get1_EC_KEY( $b_s_priv_pkey );
  my $b_sig         = Crypt::OpenSSL::ECDSA::ECDSA_do_sign( $b_tbs, $b_s_priv );
  return ( $b_sig->get_r, $b_sig->get_s );
};

my $group_params = get_ec_params( $group_name );
my $group        = $group_params->{group};
my $ctx          = $group_params->{ctx};

# a->b { g^x, na
my $id_a = 'device_a';
### $id_a

my $msg1_r = a_send_msg1( $group, $random_range, $point_compress_t, \&encode_cbor, $ctx );
my ( $na, $ek_key_a_r, $msg1 ) = @{$msg1_r}{qw/na x_r msg1/};
### na: $na->to_hex

my ( $ek_a, $ek_a_priv, $ek_a_pub, $ek_a_pub_hex_compressed, $ek_a_pub_pkey, $ek_a_priv_pkey ) =
  @{$ek_key_a_r}{qw/priv_key priv_bn pub_point pub_hex pub_pkey priv_pkey/};
pem_write_evp_pkey( 'a_ek_pub.pem', $ek_a_pub_pkey, 0 );
###  $ek_a_pub_hex_compressed

pem_write_evp_pkey( 'a_ek_priv.pem', $ek_a_priv_pkey, 1 );
###  ek_a_priv: $ek_a_priv->to_hex

### msg1: unpack("H*", $msg1)
# }

# b -> a {  g^y, nb, ENC{ B, SigB(MAC(1, na, B, g^y)) }
my $id_b          = 'device_b';
my $b_recv_msg1_r = b_recv_msg1( $group, $msg1, \&decode_cbor, $ctx );
my $b_send_msg2_r = b_send_msg2(
  $group, $b_recv_msg1_r, $id_b, $random_range, $point_compress_t, $hash_name, $key_len, \&encode_cbor,
  $mac_func,
  sub {
    my ( $b_tbs ) = @_;
    $sign_func->( "$Bin/b_s_priv.pem", $b_tbs );
  },
  $enc_func,
  $ctx,
);

my ( $nb, $ek_key_b_r, $derive_key_b_r, $msg2 ) = @{$b_send_msg2_r}{qw/nb y_r derive_key msg2/};
my ( $b_z,       $b_ke,            $b_km )                 = @{$derive_key_b_r}{qw/z ke km/};
my ( $b_recv_na, $b_recv_ek_a_pub, $b_recv_ek_a_pub_pkey ) = @{$b_recv_msg1_r}{qw/na  gx gx_pkey/};
my ( $ek_b,      $ek_b_priv,       $ek_b_pub, $ek_b_pub_hex_compressed, $ek_b_pub_pkey, $ek_b_priv_pkey ) =
  @{$ek_key_b_r}{qw/priv_key priv_bn pub_point pub_hex pub_pkey priv_pkey/};

### $id_b
### nb: $nb->to_hex

pem_write_evp_pkey( 'b_ek_pub.pem', $ek_b_pub_pkey, 0 );
###  $ek_b_pub_hex_compressed

pem_write_evp_pkey( 'b_ek_priv.pem', $ek_b_priv_pkey, 1 );
###  ek_b_priv: $ek_b_priv->to_hex

### msg2: unpack("H*", $msg2)
# }

# a -> b { ENC{ A, SigA(MAC(0, nb, A, g^x)) }
my $a_recv_msg2_r = a_recv_msg2(
  $group,        $msg2, $na, $ek_key_a_r,
  $hash_name,    $key_len,
  \&encode_cbor, \&decode_cbor,
  $mac_func,
  sub {
    my ( $tbs, $r, $s ) = @_;
    $sig_verify_func->( "$Bin/b_s_pub.pem", $tbs, $r, $s );
  },
  $dec_func,
  $ctx,
);

my $a_recv_ek_b_pub_pkey = evp_pkey_from_point_hex( $group, unpack( "H*", $a_recv_msg2_r->{gy} ), $ctx );
pem_write_evp_pkey( 'a_recv_b_ek_pub.pem', $a_recv_ek_b_pub_pkey, 0 );

my $a_send_msg3 = a_send_msg3(
  $id_a,
  $a_recv_msg2_r->{nb},
  $ek_key_a_r,
  $a_recv_msg2_r->{derive_key},
  \&encode_cbor,
  $mac_func,
  sub {
    my ( $tbs ) = @_;
    $sign_func->( "$Bin/a_s_priv.pem", $tbs );
  },
  $enc_func,

);

### a_send_msg3: unpack("H*", $a_send_msg3)
# }

# b recv a {  MAC(2, na, "ack")
my $msg3_verify_res = b_recv_msg3(
  $a_send_msg3,
  $b_send_msg2_r,
  \&encode_cbor, \&decode_cbor,
  $mac_func,
  sub {
    my ( $tbs, $r, $s ) = @_;
    $sig_verify_func->( "$Bin/a_s_pub.pem", $tbs, $r, $s );
  },
  $dec_func,
);
### $msg3_verify_res

my $mac4 = b_send_msg4( $b_recv_msg1_r, $b_send_msg2_r, \&encode_cbor, $mac_func );
### mac4: unpack("H*", $mac4)
# }

# a recv b {
my $res_msg4 = a_recv_msg4( $mac4, $na, $a_recv_msg2_r, \&encode_cbor, $mac_func );
###  $res_msg4
# }

# ks {
my $b_ks = derive_ks( $b_z, $b_recv_na, $nb->to_bin, $hash_name, $key_len );
### b_ks: unpack("H*", $b_ks)
my $a_ks = derive_ks( $a_recv_msg2_r->{derive_key}{z}, $na->to_bin, $a_recv_msg2_r->{nb}, $hash_name, $key_len );
### a_ks: unpack("H*", $a_ks)
# }

is( $a_ks, $b_ks, 'sigma session key' );

done_testing;

