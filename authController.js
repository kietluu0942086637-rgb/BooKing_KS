import { hash, compare } from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from '../models/User.js';
import Customer from '../models/Customer.js';

// --- CHỨC NĂNG ĐĂNG KÝ ---
export async function register(req, res) {
    const { email, password, firstName, lastName, phone, address, city, country, idNumber } = req.body;

    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ message: 'Email đã được sử dụng' });
        }

        const hashedPassword = await hash(password, 10);

        // Tạo User, không cần cung cấp ID nữa, database sẽ tự xử lý
        const newUser = await User.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            phone,
            role: 'Customer'
        });

        // Tạo Customer liên kết với User vừa tạo
        await Customer.create({
            userId: newUser.id,
            address,
            city,
            country,
            idNumber
        });

        res.status(201).json({ message: 'Đăng ký thành công!' });
    } catch (error) {
        console.error('LỖI KHI ĐĂNG KÝ:', error);
        res.status(500).json({ message: 'Đã xảy ra lỗi ở server.' });
    }
}

// --- CHỨC NĂNG ĐĂNG NHẬP ---
export async function login(req, res) {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });

        if (!user || !(await compare(password, user.password))) {
            return res.status(401).json({ message: 'Email hoặc mật khẩu không hợp lệ' });
        }
        if (user.status !== 'Active') {
            return res.status(403).json({ message: "Tài khoản của bạn đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên." });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            token,
            user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('LỖI KHI ĐĂNG NHẬP:', error);
        res.status(500).json({ message: 'Đã xảy ra lỗi ở server.' });
    }
}

