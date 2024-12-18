require "test_helper"

class TestChaCha20 < Minitest::Test
  include TestHelper

  def test_vectors
    [
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0000000000000000",
        counter: 0,
        keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "0000000000000000",
        counter: 0,
        keystream: "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0000000000000001",
        counter: 0,
        keystream: "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0100000000000000",
        counter: 0,
        keystream: "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b"
      },
      {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "0001020304050607",
        counter: 0,
        keystream: "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a"
      },
      {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "0001020304050607",
        counter: 2,
        keystream: "9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7"
      }
    ]
  end

  def test_keystream_matches_test_vectors
    test_vectors.each do |vector|
      key = read_hex(vector[:key])
      nonce = read_hex(vector[:nonce])
      counter = vector[:counter]
      keystream = read_hex(vector[:keystream])

      assert_equal keystream, Salcha::ChaCha20.new(key, nonce).keystream_block(counter).get_string
    end
  end
end
