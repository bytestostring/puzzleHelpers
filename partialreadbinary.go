func loadBin(deli int64) {
	
	db_file := "used.bin"

	f, err := os.Open(db_file)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		panic(err)
	}
	colls := 0
	size := stat.Size()
	limit := int(size/deli)
	usedbin = make(map[[8]byte]struct{}, limit/8)
	n := 65536
	buf := make([]byte, n)
	var bts [8]byte
	part_readed := 0
	old_generic_len := len(generic)
	var md5t [8]byte 

	for {
		x, err := f.Read(buf)
		part_readed += x
		start := 0
		bs := x/8
		for i := 0; i < bs; i++ {
			fact := 8 * (i + 1)
			copy(bts[:], buf[start:fact])
			if _, ok := usedbin[bts]; ok  {
				colls++
			}
			usedbin[bts] = struct{}{}
			start = fact
		}
		if part_readed >= limit || err == io.EOF {
			fmt.Println("Read:", part_readed, "Limit:", limit)
			fmt.Println("Partial reading reached limit, handling...")
			part_readed = 0
			out := 0
			for gi, _ := range generic {
				md5_tmp := md5.Sum([]byte(generic[gi]))
				copy(md5t[:], md5_tmp[:8])
				if _, ok := usedbin[md5t]; !ok  {
					generic[out] = generic[gi]
					out++
					continue
				}
			}
			generic = generic[:out]
			fmt.Println("Removed", (old_generic_len-len(generic)), "elements")
			old_generic_len = len(generic)
			fmt.Println("Current count of elements:", old_generic_len)
			for k := range usedbin {
				delete(usedbin, k)
			}
			if err == io.EOF {
				break
			}
		}
	}
	fmt.Println("Hashes have", colls, "collisions")
	fmt.Println("Elements removed:", (old_generic_len-len(generic)))
	fmt.Println("Creating used .txt/.bin files")
//	createUsed()
}
