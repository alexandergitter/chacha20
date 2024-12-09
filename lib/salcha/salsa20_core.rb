module Salcha
  class Salsa20Core
    def initialize(key, nonce)
      raise ArgumentError, "key must be 32 bytes" unless key.bytesize == 32
      raise ArgumentError, "nonce must be 8 bytes" unless nonce.bytesize == 8
      @matrix = prepare_matrix(key, nonce)
    end

    def block_size = 64

    def keystream_block(c)
      c_bytes = case c
                when Integer
                  raise ArgumentError, "counter overflow - must not be more than 8 bytes" unless c.size <= 8
                  [c].pack("Q<")
                when String
                  raise ArgumentError, "counter must be 8 bytes" unless c.bytesize == 8
                  c
                else
                  raise ArgumentError, "counter must be an integer or a string"
                end

      @matrix[8], @matrix[9] = c_bytes.unpack("L<2")
      salsa20_hash(@matrix)
    end

    private

    def prepare_matrix(key, nonce)
      sigma = "expand 32-byte k".unpack("L<4")
      k = key.unpack("L<8")
      n = nonce.unpack("L<2")
      [
        sigma[0], k[0], k[1], k[2],
        k[3], sigma[1], n[0], n[1],
        # two 0s as placeholder for counter
        0, 0, sigma[2], k[4],
        k[5], k[6], k[7], sigma[3]
      ]
    end

    def leftrotate32(u, c)
      ((u << c) & 0xffffffff) | (u >> (32 - c))
    end

    def salsa20_hash(xs)
      z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15 = xs

      10.times do
        z4 ^= leftrotate32((z0 + z12) & 0xffffffff, 7)
        z8 ^= leftrotate32((z4 + z0) & 0xffffffff, 9)
        z12 ^= leftrotate32((z8 + z4) & 0xffffffff, 13)
        z0 ^= leftrotate32((z12 + z8) & 0xffffffff, 18)

        z9 ^= leftrotate32((z5 + z1) & 0xffffffff, 7)
        z13 ^= leftrotate32((z9 + z5) & 0xffffffff, 9)
        z1 ^= leftrotate32((z13 + z9) & 0xffffffff, 13)
        z5 ^= leftrotate32((z1 + z13) & 0xffffffff, 18)

        z14 ^= leftrotate32((z10 + z6) & 0xffffffff, 7)
        z2 ^= leftrotate32((z14 + z10) & 0xffffffff, 9)
        z6 ^= leftrotate32((z2 + z14) & 0xffffffff, 13)
        z10 ^= leftrotate32((z6 + z2) & 0xffffffff, 18)

        z3 ^= leftrotate32((z15 + z11) & 0xffffffff, 7)
        z7 ^= leftrotate32((z3 + z15) & 0xffffffff, 9)
        z11 ^= leftrotate32((z7 + z3) & 0xffffffff, 13)
        z15 ^= leftrotate32((z11 + z7) & 0xffffffff, 18)

        z1 ^= leftrotate32((z0 + z3) & 0xffffffff, 7)
        z2 ^= leftrotate32((z1 + z0) & 0xffffffff, 9)
        z3 ^= leftrotate32((z2 + z1) & 0xffffffff, 13)
        z0 ^= leftrotate32((z3 + z2) & 0xffffffff, 18)

        z6 ^= leftrotate32((z5 + z4) & 0xffffffff, 7)
        z7 ^= leftrotate32((z6 + z5) & 0xffffffff, 9)
        z4 ^= leftrotate32((z7 + z6) & 0xffffffff, 13)
        z5 ^= leftrotate32((z4 + z7) & 0xffffffff, 18)

        z11 ^= leftrotate32((z10 + z9) & 0xffffffff, 7)
        z8 ^= leftrotate32((z11 + z10) & 0xffffffff, 9)
        z9 ^= leftrotate32((z8 + z11) & 0xffffffff, 13)
        z10 ^= leftrotate32((z9 + z8) & 0xffffffff, 18)

        z12 ^= leftrotate32((z15 + z14) & 0xffffffff, 7)
        z13 ^= leftrotate32((z12 + z15) & 0xffffffff, 9)
        z14 ^= leftrotate32((z13 + z12) & 0xffffffff, 13)
        z15 ^= leftrotate32((z14 + z13) & 0xffffffff, 18)
      end

      result = IO::Buffer.new(64)
      result.set_values(
        [:u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32],
        0,
        [
          (z0 + xs[0]) & 0xffffffff,
          (z1 + xs[1]) & 0xffffffff,
          (z2 + xs[2]) & 0xffffffff,
          (z3 + xs[3]) & 0xffffffff,
          (z4 + xs[4]) & 0xffffffff,
          (z5 + xs[5]) & 0xffffffff,
          (z6 + xs[6]) & 0xffffffff,
          (z7 + xs[7]) & 0xffffffff,
          (z8 + xs[8]) & 0xffffffff,
          (z9 + xs[9]) & 0xffffffff,
          (z10 + xs[10]) & 0xffffffff,
          (z11 + xs[11]) & 0xffffffff,
          (z12 + xs[12]) & 0xffffffff,
          (z13 + xs[13]) & 0xffffffff,
          (z14 + xs[14]) & 0xffffffff,
          (z15 + xs[15]) & 0xffffffff
        ]
      )
      result
    end
  end
end
