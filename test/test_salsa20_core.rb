require "test_helper"

class TestSalsa20Core < Minitest::Test
  include TestHelper

  def setup
    @salsa20_spec = Salcha::Salsa20Specification.new(read_hex("000102030405060708090A0B0C0D0E0F00000000000000000000000000000000"), read_hex("F0E0D0C0B0A09080"))
    @salsa20_core = Salcha::Salsa20Core.new(read_hex("000102030405060708090A0B0C0D0E0F00000000000000000000000000000000"), read_hex("F0E0D0C0B0A09080"))
  end

  def test_keystream_matches_salsa20_specification
    2000.times do |c|
      assert_equal @salsa20_spec.keystream_block(c), @salsa20_core.keystream_block(c)
    end
  end
end
