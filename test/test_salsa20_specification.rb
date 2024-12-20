require "test_helper"

class TestSalsa20Specification < Minitest::Test
  include TestHelper

  def setup
    @salsa20 = Salcha::Salsa20Specification.new(read_hex("0000000000000000000000000000000000000000000000000000000000000000"), read_hex("0000000000000000"))
  end

  def test_leftrotate32
    assert_equal 0x150f0fd8, @salsa20.send(:leftrotate32, 0xc0a8787e, 5)
  end

  def test_quarterround
    assert_equal [0x00000000, 0x00000000, 0x00000000, 0x00000000], @salsa20.send(:quarterround, 0x00000000, 0x00000000, 0x00000000, 0x00000000)
    assert_equal [0x08008145, 0x00000080, 0x00010200, 0x20500000], @salsa20.send(:quarterround, 0x00000001, 0x00000000, 0x00000000, 0x00000000)
    assert_equal [0x88000100, 0x00000001, 0x00000200, 0x00402000], @salsa20.send(:quarterround, 0x00000000, 0x00000001, 0x00000000, 0x00000000)
    assert_equal [0x80040000, 0x00000000, 0x00000001, 0x00002000], @salsa20.send(:quarterround, 0x00000000, 0x00000000, 0x00000001, 0x00000000)
    assert_equal [0x00048044, 0x00000080, 0x00010000, 0x20100001], @salsa20.send(:quarterround, 0x00000000, 0x00000000, 0x00000000, 0x00000001)
    assert_equal [0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3], @salsa20.send(:quarterround, 0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137)
    assert_equal [0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c], @salsa20.send(:quarterround, 0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b)
  end

  def test_rowround
    assert_equal [0x08008145, 0x00000080, 0x00010200, 0x20500000,
                  0x20100001, 0x00048044, 0x00000080, 0x00010000,
                  0x00000001, 0x00002000, 0x80040000, 0x00000000,
                  0x00000001, 0x00000200, 0x00402000, 0x88000100],
                 @salsa20.send(:rowround,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000)

    assert_equal [0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
                  0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
                  0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
                  0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d],
                 @salsa20.send(:rowround,
                              0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                              0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                              0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                              0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a)
  end

  def test_columnround
    assert_equal [0x10090288, 0x00000000, 0x00000000, 0x00000000,
                  0x00000101, 0x00000000, 0x00000000, 0x00000000,
                  0x00020401, 0x00000000, 0x00000000, 0x00000000,
                  0x40a04001, 0x00000000, 0x00000000, 0x00000000],
                 @salsa20.send(:columnround,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000)

    assert_equal [0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
                  0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
                  0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
                  0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8],
                 @salsa20.send(:columnround,
                              0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                              0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                              0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                              0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a)
  end

  def test_doubleround
    assert_equal [0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
                  0x08000090, 0x02402200, 0x00004000, 0x00800000,
                  0x00010200, 0x20400000, 0x08008104, 0x00000000,
                  0x20500000, 0xa0000040, 0x0008180a, 0x612a8020],
                 @salsa20.send(:doubleround,
                              0x00000001, 0x00000000, 0x00000000, 0x00000000,
                              0x00000000, 0x00000000, 0x00000000, 0x00000000,
                              0x00000000, 0x00000000, 0x00000000, 0x00000000,
                              0x00000000, 0x00000000, 0x00000000, 0x00000000)

    assert_equal [0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
                  0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
                  0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
                  0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277],
                 @salsa20.send(:doubleround,
                              0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
                              0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
                              0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
                              0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1)
  end

  def test_salsa20_hash
    x = IO::Buffer.new(64)
    x.set_values(
      [:U8]*64, 0,
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    )
    assert_equal [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                 @salsa20.send(:salsa20_hash, x).values(:U8, 0)

    x.set_values(
      [:U8]*64, 0,
      [211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
       49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
       31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
       79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54]
    )
    assert_equal [109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154,
                  29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
                  118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
                  219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202],
                 @salsa20.send(:salsa20_hash, x).values(:U8, 0)

    x.set_values(
      [:U8]*64, 0,
      [88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243,
       191, 187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37,
       86, 16, 179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48,
       238, 55, 204, 36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113]
    )
    assert_equal [179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158,
                  26, 110, 170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
                  69, 144, 51, 57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48,
                  27, 111, 114, 114, 118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35],
                 @salsa20.send(:salsa20_hash, x).values(:U8, 0)

    # x.set_values(
    #   [:U8]*64, 0,
    #   [6, 124, 83, 146, 38, 191, 9, 50, 4, 161, 47, 222, 122, 182, 223, 185,
    #    75, 27, 0, 216, 16, 122, 7, 89, 162, 104, 101, 147, 213, 21, 54, 95,
    #    225, 253, 139, 176, 105, 132, 23, 116, 76, 41, 176, 207, 221, 34, 157, 108,
    #    94, 94, 99, 52, 90, 117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186]
    # )
    # z = x.clone
    # 1000000.times { z = @salsa20.send(:salsa20_hash, z) }
    # assert_equal [8, 18, 38, 199, 119, 76, 215, 67, 173, 127, 144, 162, 103, 212, 176, 217,
    #               192, 19, 233, 33, 159, 197, 154, 160, 128, 243, 219, 65, 171, 136, 135, 225,
    #               123, 11, 68, 86, 237, 82, 20, 155, 133, 189, 9, 83, 167, 116, 194, 78,
    #               122, 127, 195, 185, 185, 204, 188, 90, 245, 9, 183, 248, 226, 85, 245, 104],
    #              z.values(:U8, 0)
  end

  def test_salsa20_expand
    assert_equal [69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98,
                  89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126,
                  104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246, 184,
                  177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103, 246, 74],
                 @salsa20.send(:salsa20_expand,
                              [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                               201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216].pack("C*"),
                              [101, 102, 103, 104, 105, 106, 107, 108, 109,110,111,112,113,114,115,116].pack("C*")).values(:U8, 0)
  end

  def keystream_test_vectors
    [
      {
        k: "8000000000000000000000000000000000000000000000000000000000000000",
        n: "0000000000000000",
        stream: [
          {
            c: "0000000000000000",
            r: "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117"
          },
          {
            c: "0300000000000000",
            r: "57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17"
          },
          {
            c: "0400000000000000",
            r: "958211C4BA2EBD5838C635EDB81F513A91A294E194F1C039AEEC657DCE40AA7E7C0AF57CACEFA40C9F14B71A4B3456A63E162EC7D8D10B8FFB1810D71001B618"
          },
          {
            c: "0700000000000000",
            r: "696AFCFD0CDDCC83C7E77F11A649D79ACDC3354E9635FF137E929933A0BD6F5377EFA105A3A4266B7C0D089D08F1E855CC32B15B93784A36E56A76CC64BC8477"
          }
        ]
      },
      {
        k: "0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
        n: "0D74DB42A91077DE",
        stream: [
          {
            c: "0000000000000000",
            r: "F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71"
          },
          {
            c: "FF03000000000000",
            r: "B70C50139C63332EF6E77AC54338A4079B82BEC9F9A403DFEA821B83F7860791650EF1B2489D0590B1DE772EEDA4E3BCD60FA7CE9CD623D9D2FD5758B8653E70"
          },
          {
            c: "FF07000000000000",
            r: "A13FFA1208F8BF50900886FAAB40FD10E8CAA306E63DF39536A1564FB760B242A9D6A4628CDC878762834E27A541DA2A5E3B3445989C76F611E0FEC6D91ACACC"
          },
        ]
      }
    ]
  end

  def test_salsa20_keystream_block
    keystream_test_vectors.each do |vector|
      k = read_hex(vector[:k])
      n = read_hex(vector[:n])
      vector[:stream].each do |stream|
        c = read_hex(stream[:c])
        r = read_hex(stream[:r])
        assert_equal r, @salsa20.send(:salsa20_keystream_block, k, n, c).get_string
      end
    end
  end

  def test_salsa20_keystream_block_integer_counter
    assert_equal read_hex("A13FFA1208F8BF50900886FAAB40FD10E8CAA306E63DF39536A1564FB760B242A9D6A4628CDC878762834E27A541DA2A5E3B3445989C76F611E0FEC6D91ACACC"),
                 @salsa20.send(:salsa20_keystream_block, read_hex("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"), read_hex("0D74DB42A91077DE"), 2047).get_string
  end
end
