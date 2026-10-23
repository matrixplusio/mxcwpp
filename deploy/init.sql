-- Matrix Cloud Security Platform 数据库初始化
-- 此脚本会在 MySQL 容器首次启动时执行
-- 表结构由应用程序自动创建 (Gorm AutoMigrate)

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS mxcwpp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE mxcwpp;
